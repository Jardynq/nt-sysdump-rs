#[cfg(feature = "no_std")]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::LoadFile;
use crate::image::{Arch, ImageError};

include!(concat!(env!("OUT_DIR"), "/versions.rs"));
include!(concat!(env!("OUT_DIR"), "/nt64.rs"));
include!(concat!(env!("OUT_DIR"), "/nt86.rs"));
include!(concat!(env!("OUT_DIR"), "/win64.rs"));
include!(concat!(env!("OUT_DIR"), "/win86.rs"));

fn copy(
    map: &phf::Map<u32, phf::Map<&'static str, u16>>,
    key: u32,
) -> Result<Vec<(String, u32)>, ImageError> {
    map.get(&key)
        .map(|inner| {
            inner
                .entries()
                .map(|(k, v)| (k.to_string(), *v as u32))
                .collect()
        })
        .ok_or(ImageError::ImageNotFound)
}

pub(crate) fn method_static(
    version: u32,
    arch: &Arch,
    file: &LoadFile,
) -> Result<Vec<(String, u32)>, ImageError> {
    let first = VERSIONS[0];
    let last = *VERSIONS.last().unwrap();
    if version < first || version > last {
        return Err(ImageError::UnsupportedVersion(version));
    }

    let mut simple = last;
    for window in VERSIONS.windows(2) {
        let low = window[0];
        let high = window[1];
        if version >= low && version < high {
            simple = low;
            break;
        }
    }

    let out = match (file, arch) {
        (LoadFile::Ntdll(_), Arch::X64) => copy(&SYSCALLS_NTDLL64, simple),
        (LoadFile::Ntdll(_), Arch::X86) => copy(&SYSCALLS_NTDLL32, simple),
        (LoadFile::Win32u(_), Arch::X64) => copy(&SYSCALLS_WIN64, simple),
        (LoadFile::Win32u(_), Arch::X86) => copy(&SYSCALLS_WIN32, simple),
        _ => unimplemented!(),
    };
    match out {
        Ok(mut out) => {
            out.sort_unstable_by(|(_, a), (_, b)| a.cmp(b));
            Ok(out)
        }
        Err(e) => Err(e),
    }
}
