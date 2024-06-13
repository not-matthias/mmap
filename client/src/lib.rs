use crate::error::ClientError;
use crate::mmap::ManualMapper;
use ntapi::ntexapi::{
    NtQuerySystemInformation, SystemProcessInformation, SYSTEM_PROCESS_INFORMATION,
};
use pelite::util::CStr;
use std::ptr;
use winapi::shared::minwindef::{FALSE, ULONG};
use winapi::shared::ntdef::NULL;
use winapi::shared::ntstatus::{STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};

use winapi::um::processthreadsapi::{CreateRemoteThread, GetCurrentProcess, OpenProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PROCESS_ALL_ACCESS, PVOID,
};

pub mod error;
pub mod mmap;

pub type DllEntrypoint = unsafe extern "C" fn(module: u64, reason: u32, reserved: u64) -> bool;

#[derive(Debug)]
pub struct Process {
    handle: HANDLE,
}

impl Process {
    /// Opens the current process.
    pub fn current() -> Option<Self> {
        let handle = unsafe { GetCurrentProcess() };

        Some(Self { handle })
    }

    /// Returns the name of the specified process structure.
    /// There's some exceptions:
    /// - 0: Idle
    /// - 4: System
    fn get_process_name(process: &SYSTEM_PROCESS_INFORMATION, process_id: usize) -> String {
        let name = &process.ImageName;
        if name.Buffer.is_null() {
            match process_id {
                0 => "Idle".to_owned(),
                4 => "System".to_owned(),
                _ => format!("<no name> Process {}", process_id),
            }
        } else {
            let slice = unsafe {
                std::slice::from_raw_parts(
                    name.Buffer,
                    // The length is in bytes, not the length of string
                    name.Length as usize / std::mem::size_of::<u16>(),
                )
            };

            String::from_utf16_lossy(slice)
        }
    }

    /// Returns a list of the currently running processes.
    fn get_process_list() -> Option<Vec<(i32, String)>> {
        // https://github.com/GuillaumeGomez/sysinfo/blob/master/src/windows/system.rs#L274

        let mut process_information: Vec<u8> = Vec::with_capacity(512 * 1024);

        //
        // Get the process information
        //
        loop {
            let mut cb_needed = 0;
            let nt_status = unsafe {
                NtQuerySystemInformation(
                    SystemProcessInformation,
                    process_information.as_mut_ptr() as PVOID,
                    process_information.capacity() as ULONG,
                    &mut cb_needed,
                )
            };
            match nt_status {
                STATUS_SUCCESS => break,
                STATUS_INFO_LENGTH_MISMATCH => {
                    let new_buffer_size = if cb_needed == 0 {
                        process_information.capacity() * 2
                    } else {
                        // allocating a few more kilo bytes just in case there are some new process
                        // kicked in since new call to NtQuerySystemInformation
                        const EXTRA_BUFFER: usize = 1024 * 10;
                        cb_needed as usize + EXTRA_BUFFER
                    };
                    process_information.reserve(new_buffer_size);
                }
                _ => return None,
            }
        }

        // Parse the data block to get process information
        let mut process_list: Vec<(i32, String)> = Vec::with_capacity(500);
        let mut process_information_offset = 0;

        loop {
            // Convert to struct
            //

            #[allow(clippy::cast_ptr_alignment)]
            let p = unsafe {
                process_information
                    .as_ptr()
                    .offset(process_information_offset)
                    as *const SYSTEM_PROCESS_INFORMATION
            };
            let pi = unsafe { &*p };

            // Add to list
            //
            let pid = pi.UniqueProcessId as i32;
            let name = Self::get_process_name(pi, pi.UniqueProcessId as usize);

            process_list.push((pid, name));

            if pi.NextEntryOffset == 0 {
                break;
            }

            process_information_offset += pi.NextEntryOffset as isize;
        }

        Some(process_list)
    }

    /// Returns the process id of the specified process name.
    pub fn by_name(name: &str) -> Option<Self> {
        let process_list = Self::get_process_list()?;

        for (pid, process_name) in process_list {
            log::info!("Found process {:?}", process_name);

            if process_name == name {
                return Self::open(pid as u32);
            }
        }

        None
    }

    /// Opens the specified process.
    pub fn open(pid: u32) -> Option<Self> {
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
        if handle != INVALID_HANDLE_VALUE {
            Some(Self { handle })
        } else {
            None
        }
    }

    /// Checks whether we opened the current process.
    pub fn is_current(&self) -> bool {
        // Here `INVALID_HANDLE_VALUE` (which is just `-1`) is used a special constant
        // to indicate that the handle is for the current process.
        //
        // See: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
        //
        self.handle == INVALID_HANDLE_VALUE
    }

    /// Checks whether we opened a remote process.
    pub fn is_remote(&self) -> bool {
        !self.is_current()
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
    pub unsafe fn alloc(&self, image_size: usize) -> Result<*mut u8, ClientError> {
        let memory = VirtualAllocEx(
            self.handle,
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

    /// Copies the specified memory to the destination pointer in the current process.
    pub unsafe fn copy_memory(&self, dst_ptr: *mut u8, data: Vec<u8>) -> Result<(), ClientError> {
        let result = WriteProcessMemory(
            self.handle,
            dst_ptr as _,
            data.as_ptr() as _,
            data.len(),
            ptr::null_mut(),
        );
        if result != FALSE {
            Ok(())
        } else {
            Err(ClientError::CopyMemory(GetLastError()))
        }
    }

    /// Manual maps the specified dll into the specified process.
    ///
    /// ## Parameters
    ///
    /// - `process`: If `None`, the current process is used.
    /// - `dll`: The bytes of the dll that should be injected.
    ///
    pub fn manual_map(&self, dll: &'static [u8]) -> Result<(), ClientError> {
        let mut mm = ManualMapper::new(dll);

        // Allocate memory
        //
        log::info!("Allocating memory in target process");
        let image_size = mm.image_size();
        let memory = unsafe { self.alloc(image_size) }?;

        // Map image and copy into target process
        //
        log::info!("Mapping image into target process");
        let (image, entrypoint) = mm
            .mmap_image(memory as *mut _ as usize, |module, import| {
                resolve_import(module, import)
            })
            .map_err(ClientError::MapImage)?;

        unsafe { self.copy_memory(memory, image) }?;

        // Call entrypoint
        //
        unsafe { self.call_entrypoint(memory as usize, entrypoint)? };

        Ok(())
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
    pub unsafe fn call_entrypoint(
        &self,
        image_base: usize,
        entrypoint: usize,
    ) -> Result<(), ClientError> {
        if self.is_remote() {
            // Create the shellcode that calls the entry point.
            //
            #[rustfmt::skip]
            let mut shellcode = vec![
                0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 28h
                0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, image_base  ; hinstDLL
                0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00,                   // mov rdx, 1           ; fdwReason
                0x4d, 0x31, 0xC0,                                           // xor r8, r8           ; lpvReserved
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, entrypoint
                0xFF, 0xD0,                                                 // call rax
                0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 28h
                0xC3,                                                       // ret
            ];

            (shellcode.as_mut_ptr().offset(6) as *mut u64).write_volatile(image_base as u64);
            (shellcode.as_mut_ptr().offset(26) as *mut u64).write_volatile(entrypoint as u64);

            // Allocate the shellcode in the target process and call it
            //
            let memory = self.alloc(shellcode.len())?;
            log::info!("Shellcode memory allocated at {:x}", memory as usize);

            log::info!("Copying shellcode into target process");
            self.copy_memory(memory, shellcode)?;

            log::info!("Creating thread to execute shellcode in target process");
            let thread_handle = CreateRemoteThread(
                self.handle,
                ptr::null_mut(),
                0,
                Some(std::mem::transmute(memory as usize)),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            );
            if thread_handle == INVALID_HANDLE_VALUE {
                return Err(ClientError::CreateRemoteThread(GetLastError()));
            }

            log::info!("Waiting for thread to finish");
            WaitForSingleObject(thread_handle, INFINITE);
        } else {
            log::info!("Calling entrypoint in current process at {:x}", entrypoint);

            let entrypoint = core::mem::transmute::<_, DllEntrypoint>(entrypoint);

            (entrypoint)(0, DLL_PROCESS_ATTACH, 0);
        }

        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

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
