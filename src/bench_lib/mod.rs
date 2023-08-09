pub mod benchmark;
mod cachegrind;
mod runner;

pub use benchmark::Benchmark;
pub use runner::main;

pub fn black_box<T>(dummy: T) -> T {
    unsafe {
        let ret = std::ptr::read_volatile(&dummy);
        std::mem::forget(dummy);
        ret
    }
}
