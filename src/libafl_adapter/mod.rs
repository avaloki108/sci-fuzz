//! LibAFL integration adapter for chimerafuzz.
//!
//! Bridges chimerafuzz's EVM execution engine with LibAFL's fuzzing
//! framework so LibAFL drives coverage-guided mutation while chimerafuzz
//! handles all EVM semantics.
//!
//! ## Phases
//!
//! | Phase | Module       | Status      |
//! |-------|-------------|-------------|
//! | 1     | `input`      | ✅ Complete |
//! | 2     | `executor`   | 🔜 Next     |
//! | 2     | `observer`   | 🔜 Next     |
//! | 3     | `mutators`   | ⬜ Pending  |
//! | 5     | `scheduler`  | ⬜ Pending  |
//! | 6     | `campaign`   | ⬜ Pending  |
//! | 7     | `concolic`   | ⬜ Pending  |

pub mod input;
pub use input::EvmInput;

pub mod observer;
pub use observer::{EvmCoverageObserver, LibAflEvmExecutor, SharedCoverageMap, MAP_SIZE};

pub mod mutators;
pub use mutators::{AbiCalldataMutator, SenderValueMutator, SequenceStructureMutator, SpliceMutator, HavocMutator};

pub mod cmplog;
pub use cmplog::CmpLogMutator;

pub mod scheduler;
pub use scheduler::{make_rand, CorpusStats};
// build_coverage_pipeline! macro is exported at crate root via #[macro_export]

// pub mod campaign;   // Phase 6
// pub mod campaign;   // Phase 6
// pub mod concolic;   // Phase 7
