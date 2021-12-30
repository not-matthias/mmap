#![feature(core_intrinsics)]

use client::alloc;
use client::mmap::{get_import, ManualMapper};
use simple_logger::SimpleLogger;
use std::arch::asm;
use std::intrinsics::breakpoint;
use std::ptr;
use winapi::um::winnt::DLL_PROCESS_ATTACH;

pub type DllEntrypoint =
    unsafe extern "C" fn(hinst_dll: u64, reason: u32, lpv_reserved: u64) -> bool;

fn main() {
    SimpleLogger::new().init().unwrap();

    // let bytes = include_bytes!("../hello-world-x64.dll");
    let bytes = include_bytes!("../../target/release/example.dll");
    let mut mm = ManualMapper::new(bytes);

    let image_size = mm.image_size();
    let memory = unsafe { alloc(image_size) }.unwrap();
    let image_base = memory as *mut _ as usize;

    println!("{:x?}", image_base);

    let (image, entrypoint) = mm
        .mmap_image(image_base, |module, function| get_import(module, function))
        .unwrap();

    // Copy image to the allocated memory
    //
    unsafe { ptr::copy_nonoverlapping(image.as_ptr() as *const u8, memory, image.len()) };

    println!("image_base: {:x?}", image_base);
    println!("entrypoint: {:x?}", entrypoint);

    // Call the entry point
    //
    let entrypoint = unsafe { entrypoint as *mut u64 as *const fn() };
    println!("{:x?}", entrypoint);

    let entrypoint = unsafe { core::mem::transmute::<_, extern "C" fn(u64, u32, u64)>(entrypoint) };
    println!("{:x?}", entrypoint as *const fn());

    let result = unsafe { (entrypoint)(0, DLL_PROCESS_ATTACH, 0) };

    std::fs::write("payload.dll", image).unwrap();
}
