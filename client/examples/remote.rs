use client::Process;
use simple_logger::SimpleLogger;

fn main() {
    SimpleLogger::new().init().unwrap();

    let bytes = include_bytes!("../../target/release/example.dll");

    let process = Process::by_name("dummy.exe").expect("Failed to open process");
    process.manual_map(bytes).expect("Failed to map process");
}
