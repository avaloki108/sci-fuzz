# Sci-Fuzz Design Document

## Overview

Sci-Fuzz is a next-generation smart contract fuzzer designed to overcome fundamental limitations in existing tools like Echidna and Forge. While these tools excel at specific tasks (Echidna at property falsification, Forge at developer workflow integration), they struggle with:

1. **Deep state exploration**: Reaching interesting contract states requires re-executing long transaction sequences
2. **Oracle burden**: Manual invariant writing dominates audit setup time
3. **Integration friction**: Tools don't seamlessly fit into existing development workflows
4. **Real-world realism**: Forked chain state fuzzing is slow and cumbersome

Sci-Fuzz addresses these challenges through a novel architecture based on peer-reviewed research and practical benchmarking evidence.

## Core Architectural Principles

### 1. State-First Exploration
Treat contract states as first-class citizens, not just transaction sequences. Store intermediate EVM states as snapshots for O(1) time-travel.

### 2. Hybrid Guidance
Combine multiple feedback mechanisms: coverage, dataflow waypoints, comparison waypoints, and concolic execution—each activated based on context and budget.

### 3. Oracle Automation
Reduce manual specification through template libraries, automatic invariant suggestion, and economic/profit-based oracles.

### 4. Ecosystem Integration
Treat Foundry as the lingua franca, not competition. Emit Forge-ready artifacts and reuse existing infrastructure where possible.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Sci-Fuzz CLI                        │
│  • Unified interface for all modes                      │
│  • Campaign configuration & management                  │
│  • Result presentation & export                         │
└─────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────┐
│               Orchestration Layer                       │
│  • Multi-armed scheduler (states vs transactions)       │
│  • Resource allocation & worker management              │
│  • Feedback aggregation & campaign statistics           │
│  • Timeout & termination handling                       │
└─────────────────────────────────────────────────────────┘
                                │
    ┌───────────────────────────┼───────────────────────────┐
    │                           │                           │
┌───▼──────┐             ┌─────▼──────┐             ┌─────▼──────┐
│  State    │             │   Hybrid   │             │   Oracle   │
│  Corpus   │             │   Engine   │             │   Engine   │
├───────────┤             ├────────────┤             ├────────────┤
│• Snapshots│             │• Coverage  │             │• Templates │
│• Waypoints│             │• Concolic  │             │• Suggestion│
│• Eviction │             │• Scheduling│             │• Economic  │
│• Pruning  │             │• Mutation  │             │• Differential│
└───────────┘             └────────────┘             └────────────┘
                                │
┌─────────────────────────────────────────────────────────┐
│              Execution Layer                            │
│  • REVM integration (local execution)                   │
│  • RPC integration (forked execution)                   │
│  • Foundry project parsing & test runner integration    │
│  • Snapshot creation & restoration                      │
└─────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────┐
│              Storage Layer                              │
│  • Snapshot corpus persistence                          │
│  • Coverage database                                    │
│  • Finding & exploit storage                            │
│  • Campaign state checkpointing                         │
└─────────────────────────────────────────────────────────┘
```

## Component Details

### 1. State-Corpus Engine

The state-corpus engine implements the snapshot-based approach from the ItyFuzz research paper, with enhancements for production use.

#### Snapshot Representation
```rust
struct Snapshot {
    id: SnapshotId,
    parent_id: Option<SnapshotId>,
    storage: HashMap<Address, StorageState>,
    balances: HashMap<Address, u128>,
    block: BlockContext,
    coverage: Coverage,
    creating_transaction: Option<Transaction>,
    metadata: SnapshotMetadata,
}
```

#### Waypoint Strategies

**Dataflow Waypoints**: Prioritize states based on "future" memory-load behavior. States that enable novel dataflows (e.g., accessing previously unread storage slots) receive higher scores.

**Comparison Waypoints**: Compress/prune the state corpus by identifying similar states. States with high similarity to existing snapshots receive lower uniqueness scores and are candidates for pruning.

#### Pruning Algorithm

The pruning algorithm uses a composite score:
```
prune_score = 
  interestingness × 2.0 +
  dataflow_score × 1.5 + 
  comparison_score × 1.0 +
  (exploration_count × -0.5) +  // Negative: explored states less valuable
  depth × 0.3                    // Deeper states more valuable
```

Snapshots with the lowest scores are pruned first when the corpus exceeds `max_snapshots`.

#### State Scheduling

A multi-armed bandit algorithm allocates exploration budget between:
1. Exploring new states from promising snapshots
2. Deepening exploration from existing high-interest states
3. Broadening exploration from shallow states

### 2. Hybrid Guidance System

#### Coverage-Guided Fuzzing
- Basic block coverage via EVM instrumentation
- Edge coverage (from->to basic blocks)
- Path coverage (sequences of basic blocks)
- Storage access coverage (unique slots read/written)

#### Concolic Execution Assist
- Triggered when mutation stalls (no new coverage for N iterations)
- Budget-limited (e.g., 10% of total execution time)
- Scope-limited to local constraint problems (not whole-program)
- Integrated via Manticore (optional feature)

#### Mutation Strategies
1. **Bit-level mutations**: Bit flips, arithmetic increments/decrements
2. **Byte-level mutations**: Random bytes, interesting values (0, 1, MAX_INT, etc.)
3. **Sequence-level mutations**: Splice/crossover transaction sequences
4. **ABI-aware mutations**: Respect function signatures and types
5. **State-aware mutations**: Modify transactions based on current state

#### Power Scheduling
Prioritize fuzzing on code that is:
1. Recently discovered (exploration bias)
2. Constraint-heavy (concolic assist candidate)
3. Economically sensitive (balance-changing operations)
4. Security-critical (e.g., auth checks, math operations)

### 3. Oracle Engine

#### Template Library
Pre-built property suites for common patterns:
- **ERC standards**: ERC20/ERC721/ERC1155 invariants
- **Proxy safety**: Implementation/initializer patterns
- **Access control**: Owner/role-based permissions
- **Arithmetic safety**: Overflow/underflow, precision loss
- **Reentrancy**: Call-depth, balance checks
- **Economic invariants**: Supply conservation, pool ratios

#### Automatic Invariant Suggestion
Static analysis suggests likely invariants:
1. **Balance conservation**: `totalSupply == sum(balances)`
2. **Access control**: `onlyOwner` functions check `msg.sender == owner`
3. **State transitions**: Finite state machine validation
4. **Math boundaries**: `0 <= balance <= totalSupply`

#### Economic Oracles
Detect exploit conditions:
- **Profit detection**: Attacker balance increases abnormally
- **Liquidation opportunities**: Under-collateralized positions
- **Arbitrage opportunities**: Price discrepancies across pools
- **Flashloan feasibility**: Profit after borrowing and repaying

#### Differential Fuzzing
Compare:
1. Optimized vs reference implementation
2. Upgradeable vs non-upgradeable versions
3. Cross-chain implementations (L1 vs L2)
4. Different compiler versions/optimization settings

### 4. Execution Layer

#### Local Execution (REVM)
- Fast in-process EVM
- Snapshot support via database cloning
- Coverage instrumentation via patched EVM
- Deterministic execution for reproducibility

#### Forked Execution (RPC)
- Fetch state from live chains
- Cache fetched accounts/storage
- Handle chain reorgs gracefully
- Support multiple RPC providers for reliability

#### Foundry Integration
- Parse `foundry.toml` and project structure
- Extract test harnesses and setup scripts
- Emit Forge-compatible test cases
- Reuse Foundry's test runner for validation

## Integration & Workflow

### Foundry-First Approach

```bash
# Basic: Replace forge test with enhanced fuzzing
sci-fuzz test --match-test "test*" --runs 10000

# Deep state: Enable snapshot engine
sci-fuzz forge --project ./my-project --depth 50 --snapshots

# Fork mode: Fuzz deployed protocol
sci-fuzz forge --project ./my-project --fork-url $ETH_RPC_URL --fork-block 19200000

# Audit mode: Automatic vulnerability discovery
sci-fuzz audit 0x742d35Cc6634C0532925a3b844Bc9e... --rpc-url $ETH_RPC_URL
```

### CI/CD Integration

```yaml
# GitHub Actions example
name: Sci-Fuzz Security Scan
on: [push, pull_request]
jobs:
  sci-fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo install sci-fuzz
      - run: sci-fuzz ci --output-format junit --fail-on-critical
```

### Export Formats
- **JUnit XML**: CI integration
- **SARIF**: Security tool interoperability
- **Foundry tests**: Executable reproducers
- **Markdown reports**: Human-readable summaries
- **Exploit scripts**: Ready-to-run proof-of-concepts

## Performance & Evaluation

### Benchmarking Strategy

#### Daedaluzz Benchmark Suite
- Measure distinct assertion violations across stateful multi-transaction scenarios
- Compare time-to-violation curves, not just end-state totals
- Run multiple seeds to account for randomness

#### Real-World Case Studies
- Fork-based audits of deployed protocols
- Comparison with manual audit findings
- Bug bounty program validation

#### Ablation Studies
Isolate contribution of each component:
1. Snapshots only (no waypoints)
2. Waypoints only (no snapshots)
3. Coverage only (no hybrid guidance)
4. Templates only (no auto-suggestion)

### Success Metrics

**Primary Metrics:**
1. **Time-to-first-bug**: Wall-clock time to discover first critical vulnerability
2. **Bug yield**: Distinct vulnerabilities found per hour
3. **Coverage efficiency**: Basic blocks covered per second

**Secondary Metrics:**
1. **Oracle burden reduction**: Lines of manual spec per bug found
2. **Integration effort**: Time from "git clone" to meaningful fuzzing
3. **Exploit quality**: Percentage of bugs with generated proof-of-concept

## Implementation Roadmap

### Phase 1: Core Engine (v0.1-v0.3)
- [x] Basic EVM execution with REVM
- [ ] Snapshot creation/restoration
- [ ] Coverage instrumentation
- [ ] Basic mutation strategies
- [ ] Foundry project parsing

### Phase 2: Hybrid Guidance (v0.4-v0.6)
- [ ] Dataflow waypoints
- [ ] Comparison waypoints
- [ ] Concolic execution integration
- [ ] Power scheduling
- [ ] Multi-armed state scheduler

### Phase 3: Oracle Automation (v0.7-v0.9)
- [ ] Template library implementation
- [ ] Automatic invariant suggestion
- [ ] Economic oracle detection
- [ ] Differential fuzzing engine
- [ ] Exploit generation

### Phase 4: Production Ready (v1.0+)
- [ ] CLI polish and documentation
- [ ] CI/CD integration templates
- [ ] Performance optimization
- [ ] Multi-chain support
- [ ] Plugin system for custom oracles

## Research Foundation

Sci-Fuzz builds on several key research contributions:

### Core Techniques
1. **ItyFuzz: Snapshot-Based Fuzzer for Smart Contract** (ISSTA'23)
   - O(1) time-travel via state snapshots
   - Dataflow and comparison waypoints

2. **Daedaluzz: A Benchmark Generator for Smart Contract Fuzzers** (ConsenSys Diligence)
   - Systematic benchmarking methodology
   - Stateful multi-transaction scenarios

3. **Hybrid Concolic Testing** (PLDI'07, adapted for EVM)
   - Combined concrete and symbolic execution
   - Budget-aware constraint solving

### Inspiration & Prior Art
- **Echidna**: Property-based fuzzing with grammar guidance
- **Forge**: Developer workflow integration
- **Medusa**: Parallel execution with corpus guidance
- **Manticore**: Symbolic execution for EVM
- **LibAFL**: Modular fuzzing framework foundation

## Open Challenges & Future Work

### Technical Challenges
1. **Snapshot overhead**: Memory usage for deep state trees
2. **Waypoint tuning**: Optimal thresholds for different contract types
3. **Concolic scaling**: Avoiding path explosion in complex contracts
4. **Oracle false positives**: Balancing sensitivity vs. specificity

### Research Opportunities
1. **ML-guided scheduling**: Predict promising states using historical data
2. **Cross-contract analysis**: Handle proxy patterns and external calls
3. **Gas optimization oracles**: Find gas-griefing vulnerabilities
4. **Formal verification integration**: Use fuzzing to guide theorem proving

## Conclusion

Sci-Fuzz represents a holistic approach to smart contract fuzzing that addresses both technical limitations and workflow friction. By combining state-first exploration, hybrid guidance, automated oracles, and ecosystem integration, it aims to deliver measurable improvements over existing tools while remaining practical for real-world use.

The key insight is that "better" fuzzing isn't just about faster mutation or better coverage—it's about reducing the human effort required to go from deployed code to discovered vulnerabilities. Sci-Fuzz achieves this through architectural choices that automate the hard parts while integrating seamlessly with the tools developers already use.