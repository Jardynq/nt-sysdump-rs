use crate::image::*;
use crate::signature::{SigByte, sig, sig_extract_u16};

#[cfg(feature = "no_std")]
use alloc::{string::String, vec::Vec};

static NTDLL_SIG_NATIVE: &[SigByte] =
    sig!(4C 8B D1 B8 x x ? ? F6 04 25 ? ? ? ? 01 75 03 0F 05 C3 CD "2E" C3);
static NTDLL_SIG_WOW: &[SigByte] = sig!(B8 x x ? ? BA ? ? ? ? FF D2 [C2 C3]);

#[derive(Clone, Copy, PartialEq)]
pub enum NtdllMethod {
    Sorting,
    Assembly,
}

#[cfg(not(feature = "no_std"))]
pub fn from_file(
    path: &str,
    method: NtdllMethod,
    arch: Option<Arch>,
    version: Option<u32>,
) -> Result<Vec<(String, u32)>, ImageError> {
    let image = Image::from_file(path, arch, version)?;
    get_indices(&image, method)
}

#[cfg(windows)]
pub fn from_memory(
    method: NtdllMethod,
    arch: Option<Arch>,
    version: Option<u32>,
) -> Result<Vec<(String, u32)>, ImageError> {
    let image = Image::from_memory("ntdll.dll", None, arch, version)?;
    get_indices(&image, method)
}

fn get_indices(image: &Image, method: NtdllMethod) -> Result<Vec<(String, u32)>, ImageError> {
    let exports = ExportIter::new(image)?;
    match (method, &image.arch) {
        (NtdllMethod::Sorting, Arch::X64) => method_sorting(exports, NTDLL_SIG_NATIVE),
        (NtdllMethod::Sorting, Arch::X86) => method_sorting(exports, NTDLL_SIG_WOW),
        (NtdllMethod::Assembly, Arch::X64) => method_assembly(exports, NTDLL_SIG_NATIVE),
        (NtdllMethod::Assembly, Arch::X86) => method_assembly(exports, NTDLL_SIG_WOW),
    }
}

/*
    All ntdll related syscall are exported with the prefix "Zw".
    And their index is just the order they appear in memory.
    So we grab all functions that start with "Zw" and sort them,
    their sorted index is their syscall index.
*/
fn method_sorting(exports: ExportIter, _: &[SigByte]) -> Result<Vec<(String, u32)>, ImageError> {
    let mut result: Vec<(String, usize)> = exports
        .filter_map(|(name, ptr)| {
            name.starts_with(b"Zw")
                .then(|| {
                    let name = String::from_utf8(name.to_vec()).ok()?;
                    Some((name.replacen("Zw", "Nt", 1), ptr.ptr() as usize))
                })
                .flatten()
        })
        .collect();
    result.sort_unstable_by(|(_, a), (_, b)| a.cmp(b));
    result.dedup_by(|(_, a), (_, b)| a == b);
    Ok(result
        .into_iter()
        .enumerate()
        .map(|(index, (name, _))| (name, index as u32))
        .collect())
}

/*
    Extract the index directly from the assembly by pattern matching.
    Only use lowest 12 bits from index, since higher bits may contain irrelevant information.
*/
fn method_assembly(
    exports: ExportIter,
    signature: &[SigByte],
) -> Result<Vec<(String, u32)>, ImageError> {
    let mut result: Vec<(String, u32)> = exports
        .into_iter()
        .filter_map(|(name, ptr)| {
            let name = String::from_utf8(name.to_vec()).ok()?;
            let index = sig_extract_u16(ptr, signature)? as u32;
            Some((name.replacen("Zw", "Nt", 1), index & 0x1fff))
        })
        .collect();
    result.sort_unstable_by(|(_, a), (_, b)| a.cmp(b));
    result.dedup_by(|(_, a), (_, b)| *a == *b);
    Ok(result)
}
