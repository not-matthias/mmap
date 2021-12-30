use winapi::um::libloaderapi::LoadLibraryA;

fn main() {
    // Dummy process that does nothing and is just for for the injection testing.

    // Make sure all the required libraries are loaded.
    //
    unsafe {
        LoadLibraryA("user32.dll\0".as_ptr() as _);
        LoadLibraryA("kernel32.dll\0".as_ptr() as _);
    }

    println!("Started the dummy process.");
    println!("Process id: {:?}", std::process::id());

    loop {}
}
