#![feature(let_else)]

use crate::error::ClientError;
use crate::mmap::ManualMapper;
use pelite::util::CStr;
use std::{mem, ptr};
use winapi::shared::minwindef::FALSE;
use winapi::shared::ntdef::NULL;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::minwinbase::PTHREAD_START_ROUTINE;
use winapi::um::processthreadsapi::{CreateRemoteThreadEx, GetCurrentProcess, OpenProcess};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS,
};

pub mod error;
pub mod mmap;

pub type DllEntrypoint = unsafe extern "C" fn(module: u64, reason: u32, reserved: u64) -> bool;

/// Finds the specified import address in the specified module and returns it.
///
/// ## Why does this work for remote injection?
///
/// We can abuse a neat little detail in Windows. When we load a library into a process, it
/// will always be mapped at the same location. Because of this, it doesn't matter whether we
/// load it inside this process or the target process.
///
/// This is because of Copy On Write. When we load a library into a process, it
/// will be **copied** into the process's address space. This means that the library will be
/// mapped at the same location in both processes.
///
pub fn resolve_import(module: &CStr, symbol: &CStr) -> Option<usize> {
    unsafe {
        let handle = LoadLibraryA(module.as_ptr() as _);
        match GetProcAddress(handle, symbol.as_ptr() as _) as usize {
            0 => None,
            n => Some(n),
        }
    }
}

/// Allocates RWX memory in the specified process.
///
/// ## Parameters
///
/// - `process`: The process to allocate memory in. If `None`, the current process is used.
/// - `size`: The size of the memory to allocate.
///
/// ## Returns
///
/// Pointer to the allocated memory. If the allocation failed, an error is returned.
///
pub unsafe fn alloc(process: Option<u32>, image_size: usize) -> Result<*mut u8, ClientError> {
    let handle = if let Some(process) = process {
        // TODO: Close Handle and check if it's valid
        OpenProcess(PROCESS_ALL_ACCESS, FALSE, process as _)
    } else {
        GetCurrentProcess()
    };

    let memory = VirtualAllocEx(
        handle,
        ptr::null_mut(),
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if memory != NULL {
        Ok(memory as *mut u8)
    } else {
        Err(ClientError::Alloc(GetLastError()))
    }
}

pub unsafe fn copy_image(
    process: Option<u32>,
    memory: *mut u8,
    image: Vec<u8>,
) -> Result<(), ClientError> {
    let handle = if let Some(process) = process {
        // TODO: Close Handle and check if it's valid
        OpenProcess(PROCESS_ALL_ACCESS, FALSE, process as _)
    } else {
        GetCurrentProcess()
    };

    let result = WriteProcessMemory(
        handle,
        memory as _,
        image.as_ptr() as _,
        image.len(),
        ptr::null_mut(),
    );
    if result != FALSE {
        Ok(())
    } else {
        Err(ClientError::CopyImage(GetLastError()))
    }
}

/// Calls the `DllEntrypoint` of the mapped image in the specified process. There are different
/// implementations required for remote and local processes.
///
/// ## Local Process
///
/// We can just create a function pointer to the entry point and call it. This works, because the
/// memory is in the same address space.
///
/// ## Remote Process
///
/// Remote processes are a little more tricky. We have to create a thread in the target process
/// but we can't call DllEntrypoint directly because it expects 3 parameters. Instead, we have to
/// create a stub shellcode, that will just call the DllEntrypoint with the correct parameters.
///
pub unsafe fn call_entrypoint(process: Option<u32>, entrypoint: usize) -> Result<(), ClientError> {
    if let Some(process) = process {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process as _);

        // Create the shellcode that calls the entry point.
        //
        #[rustfmt::skip]
        let mut shellcode = vec![
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, entrypoint
            0x4d, 0x31, 0xC0,                                           // xor r8, r8           ; lpvReserved
            0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00,                   // mov rdx, 1           ; fdwReason
            0x48, 0x31, 0xC9,                                           // xor rcx, rcx         ; hinstDLL
            0xFF, 0xD0,                                                 // call rax
        ];
        (shellcode.as_mut_ptr().offset(2) as *mut u64).write_volatile(entrypoint as u64);

        // Allocate the shellcode in the target process and call it
        //
        let memory = alloc(Some(process), shellcode.len())?;

        log::info!(
            "Writing shellcode to target process at {:x}",
            memory as usize
        );
        copy_image(Some(process), memory, shellcode)?;

        log::info!("Creating thread to execute shellcode in target process");
        CreateRemoteThreadEx(
            handle,
            0 as _,
            0,
            mem::transmute::<_, PTHREAD_START_ROUTINE>(memory),
            0 as _,
            0 as _,
            ptr::null_mut(),
            ptr::null_mut(),
        );
    } else {
        log::info!("Calling entrypoint in current process at {:x}", entrypoint);

        let entrypoint = core::mem::transmute::<_, extern "C" fn(u64, u32, u64)>(entrypoint);

        (entrypoint)(0, DLL_PROCESS_ATTACH, 0);
    }

    Ok(())
}

/// Manual maps the specified dll into the specified process.
///
/// ## Parameters
///
/// - `process`: If `None`, the current process is used.
/// - `dll`: The bytes of the dll that should be injected.
///
pub fn manual_map(process: Option<u32>, dll: &'static [u8]) -> Result<(), ClientError> {
    let mut mm = ManualMapper::new(dll);

    // Allocate memory
    //
    log::info!("Allocating memory in target process");
    let image_size = mm.image_size();
    let memory = unsafe { alloc(process, image_size) }?;

    // Map image and copy into target process
    //
    log::info!("Mapping image into target process");
    let (image, entrypoint) = mm
        .mmap_image(memory as *mut _ as usize, |module, import| {
            resolve_import(module, import)
        })
        .map_err(|e| ClientError::MapImage(e))?;

    unsafe { copy_image(process, memory, image) }?;

    // Call entrypoint
    //
    unsafe { call_entrypoint(process, entrypoint)? };

    Ok(())
}
