use log::LevelFilter;
use simple_logger::SimpleLogger;

fn main() {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .unwrap();

    // Test with load library in current process
    //
    // client::load_library();

    // Manual map
    //
    client::manual_map();
}
