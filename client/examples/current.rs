use client::Process;
use simple_logger::SimpleLogger;

fn main() {
    SimpleLogger::new().init().unwrap();

    let bytes = include_bytes!("../../target/release/example.dll");
    Process::current()
        .expect("Failed to open process")
        .manual_map(bytes)
        .expect("Failed to map process");
}
