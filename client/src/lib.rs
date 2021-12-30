use crate::error::ManualMapError;
use server::Server;
use std::ptr;
use winapi::shared::ntdef::NULL;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::um::memoryapi::VirtualAlloc;

pub mod error;

pub fn load_library() {
    unsafe { LoadLibraryA("../target/release/example.dll\0".as_ptr() as _) };
}

/// Allocates enough virtual memory to map this PE image.
pub unsafe fn alloc(image_size: usize) -> Result<*mut u8, ManualMapError> {
    let memory = VirtualAlloc(
        ptr::null_mut(),
        image_size,
        /*MEM_COMMIT|MEM_RESERVE*/ 0x00003000,
        /*PAGE_READWRITE*/ 0x04,
    );
    if memory == NULL {
        Err(ManualMapError::Alloc(GetLastError()))
    } else {
        Ok(memory as *mut u8)
    }
}

pub fn manual_map() -> Result<(), ManualMapError> {
    // TODO: Implement process lookup

    // This has to be moved to the server.
    let mut server = Server::new(include_bytes!("../../target/release/example.dll"));

    let (image_size, process_name) = server.request_metadata();

    let memory = unsafe { alloc(image_size) }?;
    let (image, entrypoint) = server
        .request_image(memory as *mut _ as usize, vec![])
        .unwrap();

    // TODO: Request image size and allocate memory
    // TODO: Find target process iat entries
    // TODO: Get payload image and inject

    std::fs::write("payload.dll", image).unwrap();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_logger::SimpleLogger;

    #[test]
    fn test_alloc() {
        SimpleLogger::new().init().unwrap();

        let dll = include_bytes!("../../target/release/examp le.dll");
        let mut server = Server::new(dll);

        let (image_size, process_name) = server.request_metadata();

        let memory = unsafe { alloc(image_size) }.unwrap();

        let (image, entrypoint) = server
            .request_image(memory as *mut _ as usize, vec![])
            .unwrap();
        std::fs::write("payload.dll", image).unwrap();
    }
}
