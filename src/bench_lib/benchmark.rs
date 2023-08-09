use itertools::Itertools;
use std::collections::HashSet;

pub enum ReportingMode {
    /// The benchmark is not mentioned in the results
    Hidden,
    /// All instructions are reported
    AllInstructions,
    /// All instructions are reported, after subtracting the instructions of the setup code
    ///
    /// The instruction count of the setup code is obtained by running a benchmark containing only
    /// that code, possibly using `ReportingMode::Hidden`. The string parameter corresponds to the
    /// name of the benchmark.
    AllInstructionsExceptSetup(String),
}

pub struct Benchmark {
    /// The name of the benchmark, as shown in the benchmark results
    name: String,
    /// The function that should be run as part of the benchmark
    function: Box<dyn Fn() + Send + Sync>,
    /// The way instructions should be reported for this benchmark
    reporting_mode: ReportingMode,
}

impl Benchmark {
    pub fn new(name: impl Into<String>, function: impl Fn() + 'static + Send + Sync) -> Self {
        Self {
            name: name.into(),
            function: Box::new(function),
            reporting_mode: ReportingMode::AllInstructions,
        }
    }

    pub fn hidden(mut self) -> Self {
        self.reporting_mode = ReportingMode::Hidden;
        self
    }

    pub fn exclude_setup_instructions(mut self, name: String) -> Self {
        self.reporting_mode = ReportingMode::AllInstructionsExceptSetup(name);
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn run(&self) {
        (self.function)()
    }

    pub fn reporting_mode(&self) -> &ReportingMode {
        &self.reporting_mode
    }
}

/// Panics if the benchmarks are invalid
///
/// Benchmarks can be invalid because of the following reasons:
///
/// - Re-using an already defined benchmark name.
/// - Referencing a non-existing benchmark in [`ReportingMode::AllInstructionsExceptSetup`].
pub fn validate(benchmarks: &[Benchmark]) {
    // Detect duplicate definitions
    let duplicate_names: Vec<_> = benchmarks
        .iter()
        .map(|b| b.name.as_str())
        .duplicates()
        .collect();
    if !duplicate_names.is_empty() {
        panic!(
            "The following benchmarks are defined multiple times: {}",
            duplicate_names.join(", ")
        );
    }

    // Detect dangling benchmark references
    let all_names: HashSet<_> = benchmarks.iter().map(|b| b.name.as_str()).collect();
    let referenced_names: HashSet<_> = benchmarks
        .iter()
        .flat_map(|b| match &b.reporting_mode {
            ReportingMode::Hidden => None,
            ReportingMode::AllInstructions => None,
            ReportingMode::AllInstructionsExceptSetup(name) => Some(name.as_str()),
        })
        .collect();

    let undefined_names: Vec<_> = referenced_names.difference(&all_names).cloned().collect();
    if !undefined_names.is_empty() {
        panic!("The following benchmark names are referenced, but have no corresponding benchmarks: {}",
            undefined_names.join(", "));
    }
}
