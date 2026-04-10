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

use std::{sync::Arc, time::{Duration, Instant}};

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
        observer::{EvmCoverageObserver, LibAflEvmExecutor, SharedCoverageMap},
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
        let start = Instant::now();

        // Shared coverage bitmap (written by executor, read by observer).
        let shared_map = SharedCoverageMap::new();

        // Coverage pipeline: observer + feedback.
        // SAFETY: shared_map Arc is kept alive for the duration of the run.
        let (observer, mut feedback) = unsafe { build_coverage_pipeline!(shared_map) };
        let mut objective = ConstFeedback::new(false);

        // State.
        let rand = make_rand(self.seed);
        let mut state = StdState::new(
            rand,
            InMemoryCorpus::<EvmInput>::new(),
            InMemoryCorpus::<EvmInput>::new(),
            &mut feedback,
            &mut objective,
        )?;

        // Scheduler.
        let scheduler = IndexesLenTimeMinimizerScheduler::new(
            &observer,
            QueueScheduler::new(),
        );

        // Inner EVM executor.
        let inner_exec = LibAflEvmExecutor::new(
            self.evm,
            Arc::clone(&shared_map),
            self.attacker,
        );

        // Coverage observer for WithObservers wrapper.
        let cov_observer = EvmCoverageObserver::new("evm_coverage", Arc::clone(&shared_map));

        // Wrap executor with observer tuple so LibAFL can call pre/post hooks.
        let mut executor = WithObservers::new(
            inner_exec,
            tuple_list!(cov_observer),
        );

        // Mutator: use our HavocMutator as the primary driver.
        let tx_mutator = TxMutator::new(self.targets.clone());
        let mutator = HavocMutator::new(tx_mutator, 8);
        let stage = StdMutationalStage::new(mutator);
        let mut stages = tuple_list!(stage);

        // Event manager (nop — single process).
        let mut mgr = NopEventManager::new();

        // Fuzzer.
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

        // Main loop.
        fuzzer.fuzz_loop_for(
            &mut stages,
            &mut executor,
            &mut state,
            &mut mgr,
            self.max_iters,
        )?;

        let corpus_size = state.corpus().count();
        let executions = *state.executions();
        // Recover the inner executor to drain findings.
        // WithObservers doesn't expose inner directly, so we can't drain here.
        // Findings are returned as part of the executor (Phase 6 TODO: expose via observer).
        let findings: Vec<Finding> = vec![]; // TODO: wire through WithObservers in Phase 6b

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
