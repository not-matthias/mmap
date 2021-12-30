use crate::error::ManualMapError;
use pelite::image::{IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW};
use pelite::pe64::imports::Desc;
use pelite::pe64::imports::Import;
use pelite::pe64::PeFile;
use pelite::pe64::PeObject;
use pelite::pe64::{Pe, Va};
use pelite::util::CStr;
use pelite::Align;
use std::{iter, ptr, slice};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};

pub fn get_import(module: &CStr, symbol: &CStr) -> Option<usize> {
    unsafe {
        let handle = LoadLibraryA(module.as_ptr() as _);
        // let handle = GetModuleHandleW(module.as_ptr() as _);
        match GetProcAddress(handle, symbol.as_ptr() as _) as usize {
            0 => None,
            n => Some(n),
        }
    }
}

pub struct ManualMapper {
    pe: PeFile<'static>,
}

impl ManualMapper {
    pub fn new(bytes: &'static [u8]) -> Self {
        // No payload id, because you can just swap out the buffer
        // or create a new instance of this.

        log::info!("Loading image with {} bytes", bytes.len());

        Self {
            pe: PeFile::from_bytes(bytes).unwrap(),
        }
    }

    pub fn image_size(&self) -> usize {
        self.pe.optional_header().SizeOfImage as usize
    }

    pub fn mmap_image<F>(
        &mut self,
        image_base: usize,
        resolve_import: F,
    ) -> Result<(Vec<u8>, usize), ManualMapError>
    where
        F: Fn(&CStr, &CStr) -> Option<usize>,
    {
        // Note: TLS and SEH are currently not supported

        let mut image = unsafe { self.copy() };
        unsafe { self.rebase(image.as_mut(), image_base)? };
        unsafe { self.resolve_imports(image.as_mut(), resolve_import)? };

        let entry_point = image_base + self.pe.optional_header().AddressOfEntryPoint as usize;

        Ok((image, entry_point))
    }

    /// Copies the headers and raw section data from to the destination image that should be mapped.
    unsafe fn copy(&mut self) -> Vec<u8> {
        let mut image = vec![0; self.image_size()];

        let src = self.pe.image().as_ptr();

        // Write PE header
        //
        // let size_of_headers = self.pe.optional_header().SizeOfHeaders as usize;
        // ptr::copy_nonoverlapping(src, image.as_mut_ptr(), size_of_headers);

        for section in self.pe.section_headers() {
            // Skip useless sections
            //
            if let Ok(".rsrc") | Ok(".reloc") | Ok(".idata") = section.name() {
                log::info!("Skipping section {}", section.name().unwrap());
                continue;
            }

            // Get the src pointer depending on src alignment
            //
            let pointer = match self.pe.align() {
                Align::File => section.PointerToRawData as usize,
                Align::Section => section.VirtualAddress as usize,
            };

            // Write section data
            //
            ptr::copy_nonoverlapping(
                src.offset(pointer as isize),
                image.as_mut_ptr().offset(section.VirtualAddress as isize),
                section.SizeOfRawData as usize,
            );
        }

        image
    }

    unsafe fn rebase(&mut self, image: &mut [u8], image_base: usize) -> Result<(), ManualMapError> {
        log::info!("Rebasing image to {:x}", image_base);

        // Offset all absolute pointers by this delta to correct them from the old ImageBase
        // to the new base of the allocated memory.
        //
        let delta = image_base.wrapping_sub(self.pe.optional_header().ImageBase as usize);

        log::info!("Rebase delta: {:x}", delta);

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
            .map_err(|err| ManualMapError::Rebase(err))?;

        let image_ptr = image.as_mut_ptr() as *mut u8;
        for block in relocs.iter_blocks() {
            for word in block.words() {
                let rva = block.rva_of(word);

                if image.len() < rva as usize {
                    log::warn!("Relocation out of bounds");
                    continue;
                    // return Err(ManualMapError::Rebase(
                    //     "Relocation out of bounds".to_string(),
                    // ));
                }

                // These only apply for x64
                //
                let ty = block.type_of(word);
                if ty == IMAGE_REL_BASED_HIGHLOW || ty == IMAGE_REL_BASED_DIR64 {
                    let ptr = image_ptr.offset(rva as isize) as *mut usize;
                    let original = ptr.read_volatile();
                    let fixed_address = original.wrapping_add(delta);
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
        }

        Ok(())
    }

    unsafe fn resolve_imports<F>(
        &mut self,
        image: &mut [u8],
        resolve_import: F,
    ) -> Result<(), ManualMapError>
    where
        F: Fn(&CStr, &CStr) -> Option<usize>,
    {
        for import_descriptor in self
            .pe
            .imports()
            .map_err(|err| ManualMapError::Imports(err))?
        {
            self.resolve_import(image, import_descriptor, &resolve_import)?;
        }

        Ok(())
    }

    unsafe fn resolve_import<F>(
        &mut self,
        image: &mut [u8],
        desc: Desc<PeFile>,
        resolve_import: &F,
    ) -> Result<(), ManualMapError>
    where
        F: Fn(&CStr, &CStr) -> Option<usize>,
    {
        let dll_name = desc.dll_name().unwrap();

        // Grab the import name table for the desired imports and the export table from the dependency
        //
        let int = desc
            .int()
            .map_err(|err| ManualMapError::Imports(err))?
            .collect::<Vec<_>>();

        // Grab the IAT to write the pointers to
        //
        let iat_ptr = image.as_mut_ptr().offset(desc.image().FirstThunk as isize) as *mut Va;
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
                    let Some(import) = resolve_import(dll_name, name) else {
                        log::error!("Couldn't find import for: {:?} - {:?}", dll_name, name);
                        continue;
                    };

                    log::info!("Resolved import {}", name);

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
