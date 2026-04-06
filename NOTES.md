# sci-fuzz: Engineering Notes from First Real Test Drive
## 2026-04-06 — concrete-earn-v2 & infini-p runs

---

## What actually worked

**Project discovery and artifact loading** — solid. Found 287 artifacts from concrete-earn-v2, 157 from infini-p. The Foundry `out/ContractName.sol/ContractName.json` nested structure parsed correctly after fixing the `out/` dir confusion. This part is genuinely good.

**ABI-inferred invariant synthesis** — ran end-to-end on first try. Got 8 synthesized invariants on concrete-earn-v2:
- AccessControlSlotOracle on 3 contracts
- PauseStateOracle on 2 contracts  
- GetterStabilityOracle across 5 contracts

The idea is right. The synthesis is real. It printed them cleanly. First time seeing "synthesized 8 ABI-inferred invariants" print on a live target felt like actual progress.

**The fuzzing loop runs** — campaigns start, execute, save corpus, produce a report. The full pipeline (project load → deploy → fuzz → report) works without crashing. That's the baseline and it held.

**Protocol profile detection** — ERC20/ERC4626/AMM scoring worked. Contracts with `owner()`, `pause()` were correctly picked up as access-control targets.

**Economic oracles** — the existing balance/flashloan/conservation/ERC4626 checks are real. If a contract with those patterns is deployed and exploitable, the oracles would fire.

---

## What failed or was painful

### 1. setUp() cheatcodes — the #1 blocker (critical)

Every real project harness uses `setUp()` with `makeAddr()`, `vm.deal()`, `vm.prank()`, `vm.warp()`, `vm.createSelectFork()`. sci-fuzz skips or fails on any harness whose constructor or setUp() calls these.

infini-p: every single harness skipped. `RedemptionHarness`, `YieldSharingHarness`, `LockingHarness` — all gone. The harnesses that the protocol's own team wrote to fuzz it — completely bypassed.

concrete-earn-v2: `ConcreteFactoryBaseSetup` setUp failed, ran without the harness scaffolding.

**Without setUp(), the deployed contracts are naked. They have no state, no funded users, no wired dependencies. Fuzzing them is basically random noise.**

What sci-fuzz can currently deploy: contracts with zero-arg constructors or simple address/uint args. That covers ~5-10% of real protocol code.

### 2. Contracts deployed in isolation — no dependency graph (critical)

infini-p's `YieldSharing` requires `address(core)`, `address(accounting)`, `address(iusd)`, etc. sci-fuzz has no way to resolve "deploy InfiniFiCore, then deploy Accounting with core's address, then deploy YieldSharing with both." It tries to deploy each contract independently and fails on anything requiring other contracts.

The real protocol is a web of 10+ interconnected contracts. We're fuzzing the contracts but not the protocol.

### 3. No progress output during campaign run

The 60-second run on concrete-earn-v2 printed nothing while running. Just silence, then the report. For a tool that might run for hours, that's a big UX problem. Need `[campaign] 5.2k exec/s | 312k total | coverage: 847 edges | 0 findings` updating every few seconds.

### 4. Inferred invariants are too conservative or too noisy

**AccessControlSlotOracle**: fires when a slot is set to the attacker address. But this requires the attacker to *already be* in the right call path to change an owner slot. Without a funded user calling real functions, this basically never fires. It's checking the right thing but under the wrong conditions.

**SupplyIntegrityOracle**: fires on *any* storage write to a token contract without an explicit mint/burn selector. But `approve()`, `transfer()`, allowance changes — all modify storage. This would produce constant false positives on any active token.

**GetterStabilityOracle**: "indirect state mutation" — will fire constantly on any protocol where one contract legitimately triggers state changes in another (which is... all DeFi). Every ERC4626 vault deposit is an "indirect mutation" on the token.

The inferred invariants need tighter signal. They're checking real things but the trigger conditions are way too broad for noisy environments.

### 5. No results in 60 seconds (expected but still)

The concrete-earn-v2 run found nothing. This is partly expected — 60s with 1 worker on a cold corpus is basically setup. But there's no way to tell if it was even making progress or just spinning wheels.

### 6. The "campaign finished" output was almost blank

```
────────────────────────────────────────────────────
  CAMPAIGN SUMMARY
────────────────────────────────────────────────────
  Duration      : 60.1s
  Executions    : ?
  Raw findings  : 0
  Unique bugs   : 0

  ✅  No invariant violations found.
```

No execution count printed. No coverage stats. No "here's what we actually tried." Completely opaque. Did it execute 100 sequences or 10,000? Was coverage growing? Did any transactions actually succeed? Unknown.

---

## What needs to improve before this finds real bugs

### Priority 1: Proper setUp() execution (makes or breaks everything)

Need to actually run `setUp()` before fuzzing starts. This means:
- Full `vm.prank` / `vm.deal` / `vm.warp` / `vm.roll` support (partially there)
- `makeAddr(string)` cheatcode (just keccak the string to an address)
- `vm.label` (no-op is fine)
- `bound(value, min, max)` (already handled in mutations)

Without this, we can only fuzz trivial contracts.

### Priority 2: Dependency-aware deployment

Build a lightweight deployment dependency graph:
1. Contracts with zero-arg constructors → deploy first
2. Contracts that need `address(X)` → deploy after X
3. The harness constructor/setUp wires everything together

Even a heuristic "if constructor takes addresses, try to match them to already-deployed contracts by ABI compatibility" would unlock most protocols.

### Priority 3: Exec count + live progress output

Every 5 seconds: print `exec/s`, total execs, coverage edges, findings. Without this you're flying blind.

### Priority 4: Inferred invariant noise reduction

- **AccessControlSlot**: only fire if the sequence explicitly called a *non-governance* setter that changed an owner slot. Not just "slot has attacker addr" — that's too coarse. Needs better pre/post comparison.
- **SupplyIntegrity**: only fire if `totalSupply` probe (not just any storage) changed without mint/burn. Requires actually probing `totalSupply()` before/after, not just watching storage writes.
- **GetterStability**: only flag if a *pure or view function's return value* changed on a contract that wasn't in the call chain at all. Add a call chain tracker.

### Priority 5: Corpus seeding from test files

infini-p and concrete-earn-v2 both have extensive test suites. If we could extract transaction sequences from existing hardhat/foundry tests and seed the corpus with them, coverage would immediately skyrocket and the fuzzer would start from a state that actually makes sense (funded users, initialized protocol).

### Priority 6: Better harness auto-detection

The current harness detection looks for `echidna_*` or `invariant_*` function names. Both infini-p and concrete-earn-v2 use `invariant_*` — but concrete-earn ran with no found echidna properties. Check why `invariant_*` isn't being picked up.

### Priority 7: Fork mode for bounty programs

For live bounty targets (Reserve Protocol, Morpho, Euler), fork mode with a real RPC is the path to actually exercising protocol state. Need:
- `--fork-url` with the live contract addresses
- Ability to specify which contracts to target by address
- The fuzzer then generates transactions against real deployed state

This completely sidesteps the setUp problem.

---

## Honest assessment

The engine is real. The invariant system is real. The inferred synthesis works. The problem is **gap between "can fuzz contracts" and "can fuzz protocols."**

Real DeFi protocols are not standalone contracts. They are webs of contracts wired together by a deployment sequence. sci-fuzz currently handles the contracts layer. It needs to handle the deployment + initialization layer before it can produce results on programs that actually pay bounties.

The path to first finding:
1. Fork mode against a live target (bypasses setUp entirely) — **fastest path**
2. OR: implement makeAddr + dependency-aware deployment — **enables local testing**

Either one, not both. Pick the faster one (fork mode), get a finding, then come back and fix local deployment properly.

---

## What's genuinely good and shouldn't be touched

- Coverage feedback and path novelty detection
- Shrinking infrastructure  
- ERC4626/AMM/conservation economic oracles
- Corpus persistence
- The campaign report JSON structure
- ABI-aware calldata generation and tuple encoding
- Multi-actor sender pool

These are solid. Don't break them chasing the new stuff.
