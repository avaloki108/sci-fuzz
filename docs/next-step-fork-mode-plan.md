# chimerafuzz fork mode — implementation status

## Goal

Move from “campaign runs on repos” to **meaningful fork-based fuzzing** of live protocol state with actionable diagnostics when nothing fires.

## Architecture

- **`BootstrapMode`** ([`types.rs`](../src/types.rs)): `LocalDeploy` | `ForkAttach` | `ForkHybrid` (inferred from `rpc_url` + whether targets carry deployment bytecode).
- **`bootstrap` module** ([`bootstrap.rs`](../src/bootstrap.rs)): RPC preflight (`eth_getCode`, proxy hint), deploy vs attach, optional Foundry harness + `setUp()`, structured `SetupReport` / deploy failures.
- **`CampaignConfig`**: `fork_allow_local_deploy` (default `true`; **`audit` forces `false`**), `fork_expected_chain_id`, `fork_fund_addresses`, `fork_skip_corpus_load`, etc.

## CLI (Phase 1)

| Flag | Notes |
|------|--------|
| `--fork-url` | On `forge` / `test`, same as `--fork-url` (canonical). On `audit`, **visible alias** for `--rpc-url`. |
| `--fork-block-number` | Visible alias for `--fork-block` (forge) / `--block-number` (audit). |
| `chimerafuzz audit … <targets>` | One or more `0x…` addresses, **or** a **single path** to a JSON manifest file. |

### Address manifest JSON

Preferred:

```json
{
  "chain_id": 1,
  "targets": [
    { "name": "Vault", "address": "0x0000000000000000000000000000000000000001" },
    { "name": "Router", "address": "0x0000000000000000000000000000000000000002" }
  ]
}
```

Also supported: `chainId` (alias for `chain_id`), `rpcLabel`, and legacy `contracts` as `{ "Vault": "0x…" }`.

Manifest `chain_id` is applied to `CampaignConfig.fork_expected_chain_id` when set (with `FORK_CHAIN_ID` env override).

## Audit vs forge

- **`audit`**: attach-only on fork (`fork_allow_local_deploy = false`), no local `CREATE` from artifact bytecode; predeployed addresses only.
- **`forge` with `--fork-url`**: can still deploy artifacts onto the fork (`ForkHybrid`) when bytecode is present — typical for mixed workflows.

## Snapshot / reset

- **Between sequences**: existing in-process `CacheDB` snapshot corpus (unchanged).
- **`fork_skip_corpus_load`**: skip loading `seq_corpus.json` from `corpus_dir` for a fresh exploratory run (e.g. debugging reproducibility).

## What remains / blockers

- **Cheatcodes in `setUp()`**: still the main local-mode pain; fork mode bypasses for real targets.
- **Multi-worker + RPC**: still single worker when `rpc_url` is set (fork DB not shared).
- **Progress UX**: periodic stdout progress and rich `CampaignReport.telemetry` are partially wired; extend as needed.

## Example commands

```bash
# Inline addresses
chimerafuzz audit 0xVault 0xRouter --rpc-url "$ETH_RPC_URL" --timeout 300

# Manifest (single path argument)
chimerafuzz audit ./manifest.json --rpc-url "$ETH_RPC_URL" --fork-block-number 19000000

# Forge project fuzzing against a fork (hybrid deploy)
chimerafuzz forge --project ./protocol --fork-url "$ETH_RPC_URL" --fork-block-number 19000000
```

## Success criteria (phase 1)

- [x] First-class fork flags and manifest input.
- [x] Clean bootstrap path shared by `Campaign::run_with_report`.
- [x] Audit attach-only default without silent local deploy on fork.
