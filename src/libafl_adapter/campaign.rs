//! LibAFL-backed campaign loop for chimerafuzz.
//!
//! Wires all previous phases into a `StdFuzzer::fuzz_loop_for()` call.
//!
//! ## Architecture
//!
//! ```text
//! StdFuzzer
//!   ├── scheduler:  IndexesLenTimeMinimizerScheduler<QueueScheduler>
//!   ├── feedback:   MaxMapFeedback
//!   ├── objective:  ConstFeedback(false)
//!   └── stages:     [StdMutationalStage<HavocMutator>]
//!
//! WithObservers<LibAflEvmExecutor, EvmInput, (EvmCoverageObserver, ()), State>
//!   ├── runs EvmInput through revm
//!   ├── projects CoverageMap -> SharedCoverageMap
//!   └── runs OracleEngine, accumulates findings
//! ```

use std::{sync::{Arc, Mutex}, time::{Duration, Instant}};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, Testcase},
    events::NopEventManager,
    executors::WithObservers,
    feedbacks::ConstFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, HasExecutions, StdState},
    Error,
};
use libafl_bolts::rands::StdRand;
use tuple_list::tuple_list;

use crate::{
    build_coverage_pipeline,
    libafl_adapter::{
        cmplog::CmpLogMutator,
        input::EvmInput,
        mutators::HavocMutator,
        observer::{LibAflEvmExecutor, SharedCoverageMap},
        scheduler::make_rand,
    },
    mutator::TxMutator,
    types::{Address, ContractInfo, Finding},
    evm::EvmExecutor,
};

// ── Result ────────────────────────────────────────────────────────────────────

/// Result of a LibAFL-backed fuzzing campaign.
#[derive(Debug)]
pub struct LibAflCampaignResult {
    pub findings: Vec<Finding>,
    pub executions: u64,
    pub duration: Duration,
    pub corpus_size: usize,
}

// ── Campaign ──────────────────────────────────────────────────────────────────

/// A LibAFL-backed fuzzing campaign.
pub struct LibAflCampaign {
    evm: EvmExecutor,
    targets: Vec<ContractInfo>,
    attacker: Address,
    seed: u64,
    max_iters: u64,
    initial_inputs: Vec<EvmInput>,
}

impl LibAflCampaign {
    pub fn builder() -> LibAflCampaignBuilder {
        LibAflCampaignBuilder::default()
    }

    /// Run the LibAFL-backed fuzzing campaign.
    pub fn run(mut self) -> Result<LibAflCampaignResult, Error> {
        use libafl::{
            feedbacks::MaxMapFeedback,
            observers::{CanTrack, HitcountsMapObserver, StdMapObserver},
            schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
        };
        use libafl_bolts::ownedref::OwnedMutSlice;
        use crate::libafl_adapter::observer::MAP_SIZE;

        let start = Instant::now();

        // Shared coverage bitmap.
        let shared_map = SharedCoverageMap::new();

        // Build the ONE observer that both feedback and executor see.
        // We use from_mut_ptr so the raw pointer is shared by both sides.
        // SAFETY: shared_map Arc lives for the entire run.
        let observer = unsafe {
            HitcountsMapObserver::new(
                StdMapObserver::from_mut_ptr(
                    "chimera_edges",
                    shared_map.as_mut_ptr(),
                    MAP_SIZE,
                )
            ).track_indices()
        };

        let mut feedback = MaxMapFeedback::new(&observer);
        let mut objective = ConstFeedback::new(false);

        let rand = make_rand(self.seed);
        let mut state = StdState::new(
            rand,
            InMemoryCorpus::<EvmInput>::new(),
            InMemoryCorpus::<EvmInput>::new(),
            &mut feedback,
            &mut objective,
        )?;

        let scheduler = IndexesLenTimeMinimizerScheduler::new(
            &observer,
            QueueScheduler::new(),
        );

        // Executor + the SAME observer in WithObservers.
        // Shared findings sink — Arc allows reading findings after fuzz_loop_for.
        let findings_sink: Arc<Mutex<Vec<Finding>>> = Arc::new(Mutex::new(Vec::new()));

        let inner_exec = LibAflEvmExecutor::new_with_sink(
            self.evm,
            Arc::clone(&shared_map),
            self.attacker,
            Arc::clone(&findings_sink),
        );
        let mut executor = WithObservers::new(inner_exec, tuple_list!(observer));

        // Mutators + stages.
        let tx_mutator = TxMutator::new(self.targets.clone());
        let mutator = HavocMutator::new(tx_mutator, 8);
        let stage = StdMutationalStage::new(mutator);
        let mut stages = tuple_list!(stage);

        let mut mgr = NopEventManager::new();
        let mut fuzzer: StdFuzzer<_, _, _, _, _> = StdFuzzer::new(scheduler, feedback, objective);

        // Seed corpus.
        if self.initial_inputs.is_empty() {
            let seed_mutator = TxMutator::new(self.targets.clone());
            let mut rng = rand::thread_rng();
            for _ in 0..self.targets.len().max(1).min(8) {
                let tx = seed_mutator.generate(&mut rng);
                state.corpus_mut().add(Testcase::new(EvmInput::new(vec![tx])))?;
            }
        } else {
            for input in self.initial_inputs.drain(..) {
                state.corpus_mut().add(Testcase::new(input))?;
            }
        }

        fuzzer.fuzz_loop_for(
            &mut stages,
            &mut executor,
            &mut state,
            &mut mgr,
            self.max_iters,
        )?;

        let corpus_size = state.corpus().count();
        let executions = *state.executions();
        // Drain findings from the shared Arc sink.
        let findings = {
            let mut sink = findings_sink.lock().unwrap();
            std::mem::take(&mut *sink)
        };

        Ok(LibAflCampaignResult {
            findings,
            executions,
            duration: start.elapsed(),
            corpus_size,
        })
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct LibAflCampaignBuilder {
    evm: Option<EvmExecutor>,
    targets: Vec<ContractInfo>,
    attacker: Option<Address>,
    seed: u64,
    max_iters: u64,
    initial_inputs: Vec<EvmInput>,
}

impl LibAflCampaignBuilder {
    pub fn new() -> Self { Self::default() }
    pub fn evm(mut self, evm: EvmExecutor) -> Self { self.evm = Some(evm); self }
    pub fn targets(mut self, t: Vec<ContractInfo>) -> Self { self.targets = t; self }
    pub fn attacker(mut self, a: Address) -> Self { self.attacker = Some(a); self }
    pub fn seed(mut self, s: u64) -> Self { self.seed = s; self }
    pub fn max_iters(mut self, n: u64) -> Self { self.max_iters = n; self }
    pub fn initial_inputs(mut self, i: Vec<EvmInput>) -> Self { self.initial_inputs = i; self }

    pub fn build(self) -> Result<LibAflCampaign, String> {
        Ok(LibAflCampaign {
            evm: self.evm.ok_or("evm is required")?,
            targets: self.targets,
            attacker: self.attacker.unwrap_or(Address::with_last_byte(0xfe)),
            seed: self.seed,
            max_iters: if self.max_iters == 0 { 10_000 } else { self.max_iters },
            initial_inputs: self.initial_inputs,
        })
    }
}
