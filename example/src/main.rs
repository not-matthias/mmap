use log::LevelFilter;
use simple_logger::SimpleLogger;


fn main() {
    SimpleLogger::new().with_level(LevelFilter::Info).init().unwrap();

    // This should actually be loaded on the server
    //
    let dll = include_bytes!("../../target/release/example.dll");

    // Load the client and map it into the **current** process
    //
}