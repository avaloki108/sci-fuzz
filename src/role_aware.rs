//! RoleAwareSequencer: Multi-actor protocol support.
//!
//! Tracks actor roles (Attacker, User, Admin, Provider, Liquidator) and generates
//! sequences that maintain role consistency. Respects protocol semantics like
//! admin-only functions, borrower-only operations, and role state transitions.
//!
//! ## Role System
//!
//! - **Attacker**: Adversarial actor, tries to break invariants
//! - **User**: Regular user, can call most permissionless functions
//! - **Admin**: Privileged actor, can call admin-only functions
//! - **Provider**: Liquidity provider, can add/remove liquidity
//! - **Liquidator**: Can liquidate underwater positions
//!
//! ## Role State
//!
//! Each role tracks:
//! - Address (sender)
//! - Balances (tokens owned)
//! - Permissions (which selectors they can call)
//! - Positions (protocol-specific: collateral, debt, etc.)

use crate::types::{Address, Transaction, U256};
use rand::Rng;
use std::collections::{HashMap, HashSet};

/// Function selector (first 4 bytes of calldata).
pub type Selector = [u8; 4];

/// Actor roles in multi-actor protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActorRole {
    /// Adversarial actor, tries to break invariants.
    Attacker,
    /// Regular user, can call most permissionless functions.
    User,
    /// Privileged actor, can call admin-only functions.
    Admin,
    /// Liquidity provider, can add/remove liquidity.
    Provider,
    /// Can liquidate underwater positions.
    Liquidator,
}

impl ActorRole {
    /// Get all actor roles.
    pub fn all_roles() -> &'static [ActorRole] {
        static ROLES: &[ActorRole] = &[
            ActorRole::Attacker,
            ActorRole::User,
            ActorRole::Admin,
            ActorRole::Provider,
            ActorRole::Liquidator,
        ];
        ROLES
    }

    /// Get the role name for logging.
    pub fn name(&self) -> &'static str {
        match self {
            ActorRole::Attacker => "attacker",
            ActorRole::User => "user",
            ActorRole::Admin => "admin",
            ActorRole::Provider => "provider",
            ActorRole::Liquidator => "liquidator",
        }
    }
}

/// Permissions for an actor role.
#[derive(Debug, Clone, Default)]
pub struct RolePermissions {
    /// Selectors this role can call (empty = all permissionless).
    pub allowed_selectors: HashSet<Selector>,
    /// Whether this role can call admin-only functions.
    pub can_call_admin: bool,
    /// Whether this role can liquidate positions.
    pub can_liquidate: bool,
    /// Whether this role can add/remove liquidity.
    pub can_provide_liquidity: bool,
}

impl RolePermissions {
    /// Check if this role can call a selector.
    pub fn can_call(&self, selector: &Selector, is_admin_fn: bool) -> bool {
        // Admin functions require admin permission
        if is_admin_fn && !self.can_call_admin {
            return false;
        }

        // If no explicit whitelist, can call all permissionless functions
        if self.allowed_selectors.is_empty() {
            true
        } else {
            self.allowed_selectors.contains(selector)
        }
    }

    /// Add a selector to the allowed set.
    pub fn allow_selector(&mut self, selector: Selector) {
        self.allowed_selectors.insert(selector);
    }
}

/// State for a single actor.
#[derive(Debug, Clone)]
pub struct ActorState {
    /// Actor's role.
    pub role: ActorRole,
    /// Actor's address.
    pub address: Address,
    /// Token balances (token address -> balance).
    pub balances: HashMap<Address, U256>,
    /// Protocol-specific positions (e.g., collateral, debt).
    pub positions: HashMap<String, U256>,
    /// Actor's permissions.
    pub permissions: RolePermissions,
}

impl ActorState {
    /// Create a new actor with the given role and address.
    pub fn new(role: ActorRole, address: Address) -> Self {
        Self {
            role,
            address,
            balances: HashMap::new(),
            positions: HashMap::new(),
            permissions: RolePermissions::default(),
        }
    }

    /// Get the actor's balance for a token.
    pub fn balance(&self, token: Address) -> U256 {
        self.balances.get(&token).copied().unwrap_or_default()
    }

    /// Set the actor's balance for a token.
    pub fn set_balance(&mut self, token: Address, balance: U256) {
        self.balances.insert(token, balance);
    }

    /// Get a protocol-specific position value.
    pub fn position(&self, key: &str) -> U256 {
        self.positions.get(key).copied().unwrap_or_default()
    }

    /// Set a protocol-specific position value.
    pub fn set_position(&mut self, key: String, value: U256) {
        self.positions.insert(key, value);
    }
}

/// Role-aware sequencer for multi-actor protocols.
#[derive(Debug, Clone)]
pub struct RoleAwareSequencer {
    /// All actors in the protocol.
    actors: Vec<ActorState>,
    /// Address -> actor index mapping.
    address_to_actor: HashMap<Address, usize>,
    /// Admin-only selectors (from ABI analysis).
    admin_selectors: HashSet<Selector>,
}

impl RoleAwareSequencer {
    /// Create a new role-aware sequencer.
    pub fn new() -> Self {
        Self {
            actors: Vec::new(),
            address_to_actor: HashMap::new(),
            admin_selectors: HashSet::new(),
        }
    }

    /// Add an actor to the sequencer.
    pub fn add_actor(&mut self, role: ActorRole, address: Address) {
        let idx = self.actors.len();
        self.actors.push(ActorState::new(role, address));
        self.address_to_actor.insert(address, idx);

        // Set role-based permissions
        let actor = &mut self.actors[idx];
        match role {
            ActorRole::Admin => {
                actor.permissions.can_call_admin = true;
            }
            ActorRole::Liquidator => {
                actor.permissions.can_liquidate = true;
            }
            ActorRole::Provider => {
                actor.permissions.can_provide_liquidity = true;
            }
            _ => {}
        }
    }

    /// Mark a selector as admin-only.
    pub fn mark_admin_selector(&mut self, selector: Selector) {
        self.admin_selectors.insert(selector);
    }

    /// Check if a selector is admin-only.
    pub fn is_admin_selector(&self, selector: &Selector) -> bool {
        self.admin_selectors.contains(selector)
    }

    /// Get all actors.
    pub fn actors(&self) -> &[ActorState] {
        &self.actors
    }

    /// Get actor by address.
    pub fn get_actor(&self, address: Address) -> Option<&ActorState> {
        self.address_to_actor.get(&address).map(|&idx| &self.actors[idx])
    }

    /// Get mutable actor by address.
    pub fn get_actor_mut(&mut self, address: Address) -> Option<&mut ActorState> {
        let idx = self.address_to_actor.get(&address).copied()?;
        self.actors.get_mut(idx)
    }

    /// Select a valid sender for a transaction.
    ///
    /// Returns an address that has permission to call the given selector.
    pub fn select_sender_for(
        &self,
        selector: &Selector,
        rng: &mut impl Rng,
    ) -> Option<Address> {
        let is_admin = self.is_admin_selector(selector);

        // Filter actors who can call this selector
        let valid_actors: Vec<_> = self
            .actors
            .iter()
            .filter(|actor| actor.permissions.can_call(selector, is_admin))
            .collect();

        if valid_actors.is_empty() {
            None
        } else {
            let actor = valid_actors[rng.gen_range(0..valid_actors.len())];
            Some(actor.address)
        }
    }

    /// Get actors by role.
    pub fn actors_by_role(&self, role: ActorRole) -> Vec<&ActorState> {
        self.actors
            .iter()
            .filter(|actor| actor.role == role)
            .collect()
    }

    /// Swap actor roles in a transaction.
    ///
    /// Replaces the sender with another actor of a compatible role.
    pub fn swap_actor_role(
        &self,
        tx: &Transaction,
        target_role: ActorRole,
        rng: &mut impl Rng,
    ) -> Option<Transaction> {
        let same_role_actors = self.actors_by_role(target_role);
        if same_role_actors.is_empty() {
            return None;
        }

        let new_sender = same_role_actors[rng.gen_range(0..same_role_actors.len())].address;

        let mut new_tx = tx.clone();
        new_tx.sender = new_sender;
        Some(new_tx)
    }

    /// Suggest a role swap for mutation.
    ///
    /// For example, swap Attacker → User to test if a vulnerability
    /// is exploitable by regular users, or User → Admin to test
    /// privilege escalation.
    pub fn suggest_role_swap(&self, tx: &Transaction, rng: &mut impl Rng) -> Option<Transaction> {
        let current_actor = self.get_actor(tx.sender)?;

        // Suggest different roles based on current role
        let target_roles = match current_actor.role {
            ActorRole::Attacker => {
                // Attacker → User (test if regular users can exploit)
                vec![ActorRole::User]
            }
            ActorRole::User => {
                // User → Attacker (adversarial testing)
                // User → Admin (privilege escalation)
                vec![ActorRole::Attacker, ActorRole::Admin]
            }
            ActorRole::Admin => {
                // Admin → User (test if admin powers are needed)
                vec![ActorRole::User]
            }
            ActorRole::Provider => {
                // Provider → Liquidator (cross-role testing)
                vec![ActorRole::Liquidator]
            }
            ActorRole::Liquidator => {
                // Liquidator → Provider (cross-role testing)
                vec![ActorRole::Provider]
            }
        };

        // Try each target role
        for target_role in target_roles {
            if let Some(swapped) = self.swap_actor_role(tx, target_role, rng) {
                return Some(swapped);
            }
        }

        None
    }
}

impl Default for RoleAwareSequencer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn actor_role_names() {
        assert_eq!(ActorRole::Attacker.name(), "attacker");
        assert_eq!(ActorRole::Admin.name(), "admin");
    }

    #[test]
    fn actor_state_basics() {
        let mut actor = ActorState::new(ActorRole::User, Address::ZERO);
        assert_eq!(actor.role, ActorRole::User);
        assert_eq!(actor.address, Address::ZERO);

        actor.set_balance(Address::ZERO, U256::from(1000u64));
        assert_eq!(actor.balance(Address::ZERO), U256::from(1000u64));

        actor.set_position("collateral".to_string(), U256::from(500u64));
        assert_eq!(actor.position("collateral"), U256::from(500u64));
    }

    #[test]
    fn role_permissions_default() {
        let perms = RolePermissions::default();
        assert!(!perms.can_call_admin);
        assert!(!perms.can_liquidate);
        assert!(!perms.can_provide_liquidity);
        assert!(perms.allowed_selectors.is_empty());
    }

    #[test]
    fn role_permissions_can_call() {
        let mut perms = RolePermissions::default();

        // Default: can call all permissionless
        let sel = [0u8, 1, 2, 3];
        assert!(perms.can_call(&sel, false));

        // Cannot call admin functions
        assert!(!perms.can_call(&sel, true));

        // Grant admin permission
        perms.can_call_admin = true;
        assert!(perms.can_call(&sel, true));

        // Whitelist specific selectors
        perms.can_call_admin = false;
        perms.allow_selector(sel);
        assert!(perms.can_call(&sel, false));
        assert!(!perms.can_call(&[1, 2, 3, 4], false));
    }

    #[test]
    fn sequencer_add_actor() {
        let mut seq = RoleAwareSequencer::new();
        seq.add_actor(ActorRole::Admin, Address::from([1u8; 20]));
        seq.add_actor(ActorRole::User, Address::from([2u8; 20]));

        assert_eq!(seq.actors().len(), 2);
        assert!(seq.get_actor(Address::from([1u8; 20])).is_some());
        assert!(seq.get_actor(Address::from([2u8; 20])).is_some());
    }

    #[test]
    fn sequencer_admin_selectors() {
        let mut seq = RoleAwareSequencer::new();
        let admin_sel = [0u8, 1, 2, 3];
        seq.mark_admin_selector(admin_sel);

        assert!(seq.is_admin_selector(&admin_sel));
        assert!(!seq.is_admin_selector(&[1, 2, 3, 4]));
    }

    #[test]
    fn sequencer_select_sender_permissioned() {
        let mut seq = RoleAwareSequencer::new();
        let admin_addr = Address::from([1u8; 20]);
        let user_addr = Address::from([2u8; 20]);

        seq.add_actor(ActorRole::Admin, admin_addr);
        seq.add_actor(ActorRole::User, user_addr);

        let admin_sel = [0u8, 1, 2, 3];
        seq.mark_admin_selector(admin_sel);

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        // Admin-only function: only admin can call
        let sender = seq.select_sender_for(&admin_sel, &mut rng);
        assert_eq!(sender, Some(admin_addr));

        // Permissionless function: both can call
        let regular_sel = [1, 2, 3, 4];
        let sender = seq.select_sender_for(&regular_sel, &mut rng);
        assert!(sender.is_some()); // Either admin or user
    }

    #[test]
    fn sequencer_actors_by_role() {
        let mut seq = RoleAwareSequencer::new();
        seq.add_actor(ActorRole::User, Address::from([1u8; 20]));
        seq.add_actor(ActorRole::User, Address::from([2u8; 20]));
        seq.add_actor(ActorRole::Admin, Address::from([3u8; 20]));

        let users = seq.actors_by_role(ActorRole::User);
        assert_eq!(users.len(), 2);

        let admins = seq.actors_by_role(ActorRole::Admin);
        assert_eq!(admins.len(), 1);
    }

    #[test]
    fn sequencer_swap_actor_role() {
        let mut seq = RoleAwareSequencer::new();
        let user1 = Address::from([1u8; 20]);
        let user2 = Address::from([2u8; 20]);

        seq.add_actor(ActorRole::User, user1);
        seq.add_actor(ActorRole::User, user2);

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let tx = Transaction {
            sender: user1,
            ..Default::default()
        };

        let swapped = seq.swap_actor_role(&tx, ActorRole::User, &mut rng);
        assert!(swapped.is_some());
        assert_ne!(swapped.unwrap().sender, user1); // Different user
    }

    #[test]
    fn sequencer_suggest_role_swap() {
        let mut seq = RoleAwareSequencer::new();
        let attacker = Address::from([1u8; 20]);
        let user = Address::from([2u8; 20]);
        let admin = Address::from([3u8; 20]);

        seq.add_actor(ActorRole::Attacker, attacker);
        seq.add_actor(ActorRole::User, user);
        seq.add_actor(ActorRole::Admin, admin);

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        // Attacker → User swap
        let tx = Transaction {
            sender: attacker,
            ..Default::default()
        };
        let swapped = seq.suggest_role_swap(&tx, &mut rng);
        assert!(swapped.is_some());
        assert_eq!(swapped.unwrap().sender, user); // Should suggest user
    }
}
