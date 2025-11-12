#[cfg(windows)]
#[cfg(feature = "no_std")]
use alloc::{string::String, vec::Vec};

use crate::image::*;
use crate::signature::{SigByte, sig, sig_extract_u16, sig_match, sig_wide};
use crate::{LoadError, LoadMethod};

static WIN32U_SIG_NATIVE: &[SigByte] =
    sig!(4C 8B D1 B8 x x ? ? F6 04 25 ? ? ? ? 01 75 03 0F 05 C3 CD "2E" C3);
static WIN32U_SIG_WOW: &[SigByte] = sig!(B8 x x x x BA ? ? ? ? FF D2 [C2 C3]);

pub static WIN32U_WIDE2: &[SigByte] =
    sig_wide!('w', 'i', 'n', '3', '2', 'u', '.', 'd', 'l', 'l', 0);

pub static WIN32U_WIDE: [u16; 11] = [
    'w' as u16, 'i' as u16, 'n' as u16, '3' as u16, '2' as u16, 'u' as u16, '.' as u16, 'd' as u16,
    'l' as u16, 'l' as u16, 0,
];

#[cfg(not(feature = "no_std"))]
pub fn from_file(
    path: &str,
    method: LoadMethod,
    arch: Option<Arch>,
    version: Option<u32>,
) -> Result<Vec<(String, u32)>, LoadError> {
    let image = Image::from_file(path, arch, version)?;
    get_indices(&image, method)
}

#[cfg(windows)]
pub fn from_memory(
    method: LoadMethod,
    arch: Option<Arch>,
    version: Option<u32>,
) -> Result<Vec<(String, u32)>, LoadError> {
    use crate::memory::{LdrLoadDll, LdrUnloadDll};
    use windows_sys::Win32::Foundation::UNICODE_STRING;

    let image = match Image::from_memory("win32u.dll", None, arch, version) {
        Ok(image) => image,
        Err(LoadError::ImageNotFound) => {
            // win32u.dll is not loaded.
            // Use ntdll to grab LdrLoadDll and load win32u.dll.
            let image = Image::from_memory("ntdll.dll", None, None, Some(0))?;
            let mut load_fn = None;
            let mut unload_fn = None;

            for (name, ptr) in ExportIter::new(&image)? {
                if load_fn.is_some() && unload_fn.is_some() {
                    break;
                }
                if name == b"LdrLoadDll" {
                    load_fn =
                        Some(unsafe { core::mem::transmute::<*const u8, LdrLoadDll>(ptr.start()) });
                } else if name == b"LdrUnloadDll" {
                    unload_fn = Some(unsafe {
                        core::mem::transmute::<*const u8, LdrUnloadDll>(ptr.start())
                    });
                }
            }
            if load_fn.is_none() || unload_fn.is_none() {
                return Err(LoadError::InvalidExportDirectory);
            }

            unsafe {
                let mut name = UNICODE_STRING {
                    Length: (WIN32U_WIDE.len() - 1) as u16 * 2,
                    MaximumLength: WIN32U_WIDE.len() as u16 * 2,
                    Buffer: WIN32U_WIDE.as_ptr() as *mut u16,
                };
                let mut handle: usize = 0;
                let _ = load_fn.unwrap()(
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    &mut name as *mut _,
                    &mut handle as *mut usize as *mut _,
                );
            };
            Image::from_memory("win32u.dll", unload_fn, arch, version)?
        }
        Err(e) => return Err(e),
    };
    get_indices(&image, method)
}

fn get_indices(image: &Image, method: LoadMethod) -> Result<Vec<(String, u32)>, LoadError> {
    let exports = ExportIter::new(image)?;
    match (method, &image.arch) {
        (LoadMethod::Sorting, Arch::X64) => method_sorting(exports, WIN32U_SIG_NATIVE),
        (LoadMethod::Sorting, Arch::X86) => method_sorting(exports, WIN32U_SIG_WOW),
        (LoadMethod::Assembly, Arch::X64) => method_assembly(exports, WIN32U_SIG_NATIVE),
        (LoadMethod::Assembly, Arch::X86) => method_assembly(exports, WIN32U_SIG_WOW),
    }
}

/*
    Sadly win32u does not allow for the same exact trick as ntdll.
    Instead we grab all exports that have a matching byte signature,
    and then sort them. Their sorted index + 0x1000 is the syscall index.
*/
fn method_sorting(
    exports: ExportIter,
    signature: &[SigByte],
) -> Result<Vec<(String, u32)>, LoadError> {
    let mut result: Vec<(String, usize)> = exports
        .filter_map(|(name, ptr)| {
            let name = String::from_utf8(name.to_vec()).ok()?;
            sig_match(ptr, signature).then_some((name, ptr.start() as usize))
        })
        .collect();
    result.dedup_by(|(_, a), (_, b)| *a == *b);
    result.sort_unstable_by(|(_, a), (_, b)| a.cmp(b));
    Ok(result
        .into_iter()
        .enumerate()
        .map(|(index, (name, _))| (name, index as u32 + 0x1000))
        .collect())
}

/*
    Extract the index directly from the assembly by pattern matching.
    Only use lowest 12 bits from index, since higher bits might contain irrelevant information.
*/
fn method_assembly(
    exports: ExportIter,
    signature: &[SigByte],
) -> Result<Vec<(String, u32)>, LoadError> {
    let mut result: Vec<(String, u32)> = exports
        .into_iter()
        .filter_map(|(name, ptr)| {
            let name = String::from_utf8(name.to_vec()).ok()?;
            let index = sig_extract_u16(ptr, signature)? as u32;
            Some((name, index & 0x1fff))
        })
        .collect();
    result.sort_unstable_by(|(_, a), (_, b)| a.cmp(b));
    result.dedup_by(|(_, a), (_, b)| *a == *b);
    Ok(result)
}
