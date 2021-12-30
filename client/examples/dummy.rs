use std::time::Duration;

fn main() {
    // Dummy process that does nothing and is just for for the injection testing.

    println!("Started the dummy process.");
    println!("Process id: {:?}", std::process::id());

    loop {
        std::thread::sleep(Duration::from_micros(1000 / 30));
    }
}
