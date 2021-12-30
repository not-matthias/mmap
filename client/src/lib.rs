#![feature(let_else)]

use crate::error::ClientError;
use crate::mmap::ManualMapper;
use std::ptr;
use winapi::shared::ntdef::NULL;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

pub mod error;
pub mod mmap;

pub fn load_library() {
    unsafe { LoadLibraryA("../target/release/example.dll\0".as_ptr() as _) };
}

/// Allocates enough virtual memory to map this PE image.
pub unsafe fn alloc(image_size: usize) -> Result<*mut u8, ClientError> {
    let memory = VirtualAlloc(
        ptr::null_mut(),
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if memory == NULL {
        Err(ClientError::Alloc(GetLastError()))
    } else {
        Ok(memory as *mut u8)
    }
}

pub fn manual_map() -> Result<(), ClientError> {
    // TODO: Implement process lookup

    // This has to be moved to the server.
    let mut mm = ManualMapper::new(include_bytes!("../hello-world-x64.dll"));

    let image_size = mm.image_size();
    let memory = unsafe { alloc(image_size) }?;

    let (image, _entrypoint) = mm
        .mmap_image(memory as *mut _ as usize, |_, _| None)
        .unwrap();

    // TODO: Request image size and allocate memory
    // TODO: Find target process iat entries
    // TODO: Get payload image and inject

    std::fs::write("payload.dll", image).unwrap();

    Ok(())
}
