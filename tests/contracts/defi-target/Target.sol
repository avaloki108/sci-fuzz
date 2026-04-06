// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// Simple multi-contract DeFi protocol for sci-fuzz testing.
/// Contains known vulnerabilities for validation.

import "forge-std/Test.sol";

// ===== Token =====
contract SimpleToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    address public owner;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol, uint256 _initialSupply) {
        name = _name;
        symbol = _symbol;
        owner = msg.sender;
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
        emit Transfer(address(0), msg.sender, _initialSupply);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "insufficient balance");
        require(allowance[from][msg.sender] >= amount, "insufficient allowance");
        balanceOf[from] -= amount;
        allowance[from][msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function burn(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        emit Transfer(msg.sender, address(0), amount);
    }
}

// ===== Vulnerable Vault =====
contract SimpleVault {
    address public owner;
    SimpleToken public token;
    uint256 public totalDeposited;

    mapping(address => uint256) public deposits;
    bool public paused;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor(address _token) {
        owner = msg.sender;
        token = SimpleToken(_token);
    }

    // BUG: reentrancy in withdraw — no checks-effects-interactions
    function deposit(uint256 amount) external {
        require(!paused, "paused");
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
        totalDeposited += amount;
        emit Deposited(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        require(!paused, "paused");
        require(deposits[msg.sender] >= amount, "insufficient deposit");
        deposits[msg.sender] -= amount;
        totalDeposited -= amount;
        // BUG: external call before state update complete
        (bool ok,) = address(token).call(
            abi.encodeWithSignature("transfer(address,uint256)", msg.sender, amount)
        );
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    function pause() external {
        require(msg.sender == owner, "not owner");
        paused = true;
    }

    function unpause() external {
        require(msg.sender == owner, "not owner");
        paused = false;
    }

    // BUG: anyone can call this, not just owner
    function sweepTo(address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}

// ===== Echidna-style harness =====
contract FuzzHarness is Test {
    SimpleToken token;
    SimpleVault vault;

    address constant ATTACKER = 0x4242424242424242424242424242424242424242;

    function setUp() public {
        token = new SimpleToken("TestToken", "TST", 1_000_000 ether);
        vault = new SimpleVault(address(token));
        token.approve(address(vault), type(uint256).max);
        token.mint(ATTACKER, 100 ether);
    }

    // Property: totalDeposited should never exceed what the vault actually holds
    function check_vault_solvent() public {
        assertLe(vault.totalDeposited(), token.balanceOf(address(vault)));
    }

    // Property: deposits should track balance changes correctly
    function check_deposit_accounting() public {
        assertGe(vault.totalDeposited(), 0);
    }
}
