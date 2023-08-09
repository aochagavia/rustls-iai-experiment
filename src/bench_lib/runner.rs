use super::benchmark::{self, Benchmark, ReportingMode};
use super::cachegrind;
use rayon::prelude::*;
use std::collections::HashMap;

pub fn main(benchmarks: &[Benchmark]) {
    let mut args_iter = std::env::args();
    let executable = args_iter.next().unwrap();

    if let Some("--bench-run") = args_iter.next().as_deref() {
        // We are one of the child run, running under cachegrind
        run_single(&args_iter.next().unwrap(), benchmarks);
    } else {
        // We are the top-level run, running under cargo
        run_all(&executable, benchmarks);
    }
}

/// Run a single bench
fn run_single(index: &str, benchmarks: &[Benchmark]) {
    // In this branch, we're running under cachegrind, so execute the benchmark as quickly as
    // possible and exit
    let index: isize = index.parse().unwrap();

    // -1 is used as a signal to do nothing and return. By recording an empty benchmark, we can
    // subtract out the overhead from startup and dispatching to the right benchmark.
    if index == -1 {
        return;
    }

    let index = index as usize;
    benchmarks[index].run();
}

/// Run all the provided benches under cachegrind to retrieve their instruction count
fn run_all(executable: &str, benches: &[Benchmark]) {
    benchmark::validate(benches);

    if !cachegrind::check_valgrind() {
        return;
    }

    let arch = cachegrind::get_arch();
    let calibration = cachegrind::run_bench(&arch, executable, -1, "calibration");

    let results: HashMap<_, _> = benches
        .par_iter()
        .enumerate()
        .map(|(i, bench)| {
            let instr_count =
                cachegrind::run_bench(&arch, &executable, i as isize, bench.name()) - calibration;
            (bench.name(), instr_count)
        })
        .collect();

    for bench in benches {
        let instr_count = match bench.reporting_mode() {
            ReportingMode::Hidden => continue,
            ReportingMode::AllInstructions => results[bench.name()],
            ReportingMode::AllInstructionsExceptSetup(setup_name) => {
                results[bench.name()] - results[setup_name.as_str()]
            }
        };
        println!("{} : {}", instr_count, bench.name());
    }
}
