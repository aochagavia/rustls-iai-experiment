use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn check_valgrind() -> bool {
    let result = Command::new("valgrind")
        .arg("--tool=cachegrind")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match result {
        Err(e) => {
            println!("Unexpected error while launching valgrind. Error: {}", e);
            false
        }
        Ok(status) => {
            if status.success() {
                true
            } else {
                println!("Failed to launch valgrind. Error: {}. Please ensure that valgrind is installed and on the $PATH.", status);
                false
            }
        }
    }
}

pub fn run_bench(arch: &str, executable: &str, i: isize, name: &str) -> u64 {
    let output_file = PathBuf::from(format!("target/cachegrind/cachegrind.out.{}", name));
    std::fs::create_dir_all(output_file.parent().unwrap()).expect("Failed to create directory");

    // Run under setarch to disable ASLR, which could noise up the results a bit
    let mut cmd = Command::new("setarch");
    let status = cmd
        .arg(arch)
        .arg("-R")
        .arg("valgrind")
        .arg("--tool=cachegrind")
        .arg("--cache-sim=no")
        .arg(format!("--cachegrind-out-file={}", output_file.display()))
        .arg(executable)
        .arg("--bench-run")
        .arg(i.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("Failed to run benchmark in cachegrind");

    if !status.success() {
        panic!(
            "Failed to run benchmark in cachegrind. Exit code: {:?}",
            status.code()
        );
    }

    let instruction_count = parse_cachegrind_output(&output_file);
    std::fs::remove_file(output_file).ok();

    instruction_count
}

fn parse_cachegrind_output(file: &Path) -> u64 {
    let file_in = File::open(file).expect("Unable to open cachegrind output file");

    for line in BufReader::new(file_in).lines() {
        let line = line.unwrap();
        if let Some(line) = line.strip_prefix("summary: ") {
            return line
                .trim()
                .parse()
                .expect("Unable to parse summary line from cachegrind output file");
        }
    }

    panic!("Unable to parse cachegrind output file")
}

pub fn get_arch() -> String {
    let output = Command::new("uname")
        .arg("-m")
        .stdout(Stdio::piped())
        .output()
        .expect("Failed to run `uname` to determine CPU architecture.");

    String::from_utf8(output.stdout)
        .expect("`-uname -m` returned invalid unicode.")
        .trim()
        .to_owned()
}
