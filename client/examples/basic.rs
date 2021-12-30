use client::manual_map;
use simple_logger::SimpleLogger;

fn main() {
    SimpleLogger::new().init().unwrap();

    let bytes = include_bytes!("../../target/release/example.dll");
    manual_map(Some(22936), bytes).expect("Failed to manual map");
}
