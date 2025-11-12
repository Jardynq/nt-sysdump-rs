use crate::image::{Arch, ArchData, ImageError, ImageHeaders};
use core::ffi::{c_ulong, c_void};
use core::slice;
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::PEB;
use ntapi::winapi::shared::ntdef::LIST_ENTRY;
use windows_sys::Win32::Foundation::{NTSTATUS, UNICODE_STRING};
use windows_sys::core::PCWSTR;

pub(crate) type LdrLoadDll =
    unsafe extern "system" fn(PCWSTR, *mut c_ulong, *mut UNICODE_STRING, *mut c_void) -> NTSTATUS;
pub(crate) type LdrUnloadDll = unsafe extern "system" fn(*mut c_void) -> NTSTATUS;

#[derive(Clone)]
pub(crate) struct ImageMemory {
    data: &'static [u8],
    unload_fn: Option<LdrUnloadDll>,
}
impl Drop for ImageMemory {
    fn drop(&mut self) {
        if let Some(unload_fn) = self.unload_fn {
            unsafe {
                unload_fn(self.data.as_ptr() as *mut c_void);
            }
        }
    }
}
impl ImageMemory {
    pub(crate) fn data(&self) -> &'static [u8] {
        self.data
    }
    pub(crate) fn new(
        name: &str,
        unload_fn: Option<LdrUnloadDll>,
        arch: Option<Arch>,
        version: Option<u32>,
    ) -> Result<(Self, Arch, u32), ImageError> {
        let iter = ImageIter::new()?;
        for (image_name, base, size) in iter {
            if u16_str_eq(image_name, name) {
                let data = unsafe { core::slice::from_raw_parts(base as _, size) };
                let headers = ImageHeaders::new(data)?;
                let version = match version {
                    Some(version) => version,
                    None => headers.get_version()?,
                };
                let arch = match arch {
                    Some(arch) => arch,
                    None => match &headers.opt {
                        ArchData::X86(_) => Arch::X86,
                        ArchData::X64(_) => Arch::X64,
                    },
                };
                return Ok((Self { data, unload_fn }, arch, version));
            }
        }
        Err(ImageError::ImageNotFound)
    }
}

pub(crate) struct ImageIter {
    head: *const LIST_ENTRY,
    current: *const LIST_ENTRY,
}
impl ImageIter {
    pub(crate) fn new() -> Result<Self, ImageError> {
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        compile_error!("Unsupported architecture");

        unsafe {
            let peb: *mut PEB;
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
            #[cfg(target_arch = "x86")]
            core::arch::asm!("mov {}, fs:[0x30]", out(reg) peb);

            let ldr = peb
                .as_ref()
                .ok_or(ImageError::LoaderTableNotFound)?
                .Ldr
                .as_ref()
                .ok_or(ImageError::LoaderTableNotFound)?;
            let head = &ldr.InLoadOrderModuleList as *const LIST_ENTRY;
            let current = (*head).Flink;
            Ok(Self { head, current })
        }
    }
}
impl Iterator for ImageIter {
    type Item = (&'static [u16], usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.is_null() || self.head.is_null() || self.current == self.head {
            return None;
        }

        unsafe {
            let entry = self.current.cast::<LDR_DATA_TABLE_ENTRY>().as_ref()?;
            self.current = self.current.as_ref()?.Flink;

            let name_ptr = entry.BaseDllName.Buffer;
            if name_ptr.is_null() {
                return self.next();
            }

            let name = slice::from_raw_parts(name_ptr, entry.BaseDllName.Length as usize / 2);
            let base = entry.DllBase as usize;
            let size = entry.SizeOfImage as usize;

            Some((name, base, size))
        }
    }
}

fn u16_str_eq(a: &[u16], b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    for (a, b) in a.iter().zip(b.chars()) {
        if *a > 0x7F {
            return false;
        }

        let a = (*a as u8 as char).to_ascii_lowercase();
        let b = b.to_ascii_lowercase();
        if a != b {
            return false;
        }
    }
    true
}
