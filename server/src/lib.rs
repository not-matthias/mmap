#![feature(let_else)]

use crate::error::ServerError;
use pelite::pe32::imports::Import;
use pelite::pe64::exports::Export;
use pelite::pe64::imports::Desc;
use pelite::pe64::PeFile;
use pelite::pe64::{Pe, PeObject, Va};
use pelite::util::CStr;
use pelite::PeView;
use std::ffi::CString;
use std::{iter, mem, ptr, slice};
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress, LoadLibraryA};

pub mod error;

fn get_function(module: &CStr, symbol: &CStr) -> Option<usize> {
    unsafe {
        let handle = LoadLibraryA(module.as_ptr() as _);
        // let handle = GetModuleHandleW(module.as_ptr() as _);
        match GetProcAddress(handle, symbol.as_ptr() as _) as usize {
            0 => None,
            n => Some(n),
        }
    }
}

pub struct Server {
    pe: PeFile<'static>,
    image: Vec<u8>,
}

impl Server {
    pub fn new(bytes: &'static [u8]) -> Self {
        // No payload id, because you can just swap out the buffer
        // or create a new instance of this.

        Self {
            pe: PeFile::from_bytes(bytes).unwrap(),
            image: bytes.to_vec(),
        }
    }

    /// Returns the image size and the target process.
    pub fn request_metadata(&self) -> (usize, String) {
        (
            self.pe.optional_header().SizeOfImage as usize,
            "Placeholder".to_string(),
        )
    }

    pub fn request_image(
        &mut self,
        base_address: usize,
        imports: Vec<(String, usize)>,
    ) -> Result<(Vec<u8>, usize), ServerError> {
        // Note: TLS and SEH are currently not supported

        // TODO: Only send sections and not headers

        let mut image = self.image.clone();
        let entry_point = base_address + self.pe.optional_header().AddressOfEntryPoint as usize;

        unsafe { self.rebase(image.as_mut(), base_address)? };
        // unsafe { self.resolve_imports(imports)? };

        Ok((image, entry_point))
    }

    unsafe fn rebase(&mut self, image: &mut [u8], image_base: usize) -> Result<(), ServerError> {
        log::info!("Rebasing image to {:x}", image_base);

        // Offset all absolute pointers by this delta to correct them from the old ImageBase
        // to the new base of the allocated memory.
        //
        let delta = image_base.wrapping_sub(self.pe.optional_header().ImageBase as usize);

        // If the module is loaded at its preferred base address then no relocation is necessary
        //
        if delta == 0 {
            log::info!("No rebasing necessary");
            return Ok(());
        }

        // Correct all base relocations by this delta
        //
        let relocs = self
            .pe
            .base_relocs()
            .map_err(|err| ServerError::Rebase(err))?;

        let image_ptr = image.as_mut_ptr() as *mut u8;
        log::info!("Image ptr: {:p}", image_ptr);

        for block in relocs.iter_blocks() {
            for word in block.words() {
                let rva = block.rva_of(word);

                let ptr = image_ptr.offset(rva as isize) as *mut usize;
                let original = ptr.read_volatile();
                let fixed_address = original.wrapping_add(delta);

                let fixed_address = 0x41414141;
                ptr.write_volatile(fixed_address);

                log::info!(
                    "Adjusted data at {:p} (rva = {:x}) from {:x} to {:x}",
                    ptr,
                    rva,
                    original,
                    fixed_address
                );
            }
        }

        Ok(())
    }

    unsafe fn resolve_imports(&mut self, imports: Vec<(String, usize)>) -> Result<(), ServerError> {
        for import_descriptor in self.pe.imports().map_err(|err| ServerError::Imports(err))? {
            self.resolve_import(import_descriptor, &imports);
        }

        Ok(())
    }

    unsafe fn resolve_import(
        &mut self,
        import_descriptor: Desc<PeFile>,
        imports: &[(String, usize)],
    ) -> Result<(), ServerError> {
        let dll_name = import_descriptor.dll_name().unwrap();

        // Grab the import name table for the desired imports and the export table from the dependency
        //
        let int = import_descriptor
            .int()
            .map_err(|err| ServerError::Imports(err))?
            .collect::<Vec<_>>();

        // Grab the IAT to write the pointers to
        //
        let iat_ptr = self
            .image
            .as_mut_ptr()
            .offset(import_descriptor.image().FirstThunk as isize) as *mut Va;
        let iat = slice::from_raw_parts_mut(iat_ptr, int.len());

        // Resolve the imported functions one by one
        //
        for (import, dest) in iter::zip(int, iat) {
            // Read the imported function description
            // This shouldn't ever fail really, unless your PE is really corrupt...
            //
            let Ok(import) = import else { continue; };

            match import {
                Import::ByName { name, .. } => {
                    // TODO: Replace with actual lookup

                    log::info!("Resolved import {}", name);

                    let Some(import) = get_function(dll_name, name) else {
                        log::error!("Couldn't find import for: {:?} - {:?}", dll_name, name);
                        continue;
                    };

                    // And write the exported VA to the IAT
                    //
                    *dest = import as Va;
                }
                Import::ByOrdinal { .. } => {
                    todo!("Currently not supported")
                }
            }
        }

        Ok(())
    }
}
