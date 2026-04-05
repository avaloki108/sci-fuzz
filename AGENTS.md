## Learned User Preferences

- When extending sci-fuzz, prefer additive modules and small API extensions over broad campaign or engine refactors unless a brief explicitly calls for a larger change.

## Learned Workspace Facts

- Feature work in this repository is aimed at sci-fuzz’s own Rust/revm engine (execution, coverage, feedback, campaign, oracles, snapshots); building adapters or wrappers around external fuzzers (Echidna, Medusa, Manticore, ItyFuzz, Forge) is consistently treated as out of scope in session briefs.
