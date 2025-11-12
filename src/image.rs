use core::ffi::CStr;
use core::fmt::Display;
use core::mem::size_of;
use windows_sys::Win32::Storage::FileSystem::VS_FIXEDFILEINFO;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_RESOURCE,
    IMAGE_FILE_HEADER, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
    IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};

#[cfg(not(feature = "no_std"))]
use crate::file::ImageFile;
#[cfg(target_os = "windows")]
use crate::memory::{ImageMemory, LdrUnloadDll};
use crate::signature::{SigByte, sig, sig_search, sig_wide};
use crate::{LoadError, Ptr};

// 0xFEEF04BD
const VS_FIXEDVERSION_SIG: &[SigByte] = sig!(bd 04 ef fe);
const VS_VERSION_SIG: &[SigByte] = sig_wide!(
    'V', 'S', '_', 'V', 'E', 'R', 'S', 'I', 'O', 'N', '_', 'I', 'N', 'F', 'O'
);

#[derive(Clone)]
pub(crate) enum ImageType {
    #[cfg(not(feature = "no_std"))]
    File(ImageFile),
    #[cfg(target_os = "windows")]
    Memory(ImageMemory),
}

#[derive(Clone)]
pub enum ArchData<T32, T64> {
    X86(T32),
    X64(T64),
    // ARM64(T64),
}

#[derive(Clone, Copy)]
pub enum Arch {
    X86,
    X64,
    // ARM64,
    // WOW32,
}
impl Display for Arch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Arch::X86 => write!(f, "x86"),
            Arch::X64 => write!(f, "x64"),
            //Arch::ARM64 => write!(f, "arm64"),
            //Arch::WOW32 => write!(f, "wow32"),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Image {
    pub(crate) version: u32,
    pub(crate) arch: Arch,
    internal: ImageType,
}
impl Image {
    pub(crate) fn data(&self) -> &[u8] {
        match self.internal {
            #[cfg(not(feature = "no_std"))]
            ImageType::File(ref file) => file.data(),
            #[cfg(target_os = "windows")]
            ImageType::Memory(ref memory) => memory.data(),
        }
    }

    #[cfg(not(feature = "no_std"))]
    pub(crate) fn from_file(
        path: &str,
        arch: Option<Arch>,
        version: Option<u32>,
    ) -> Result<Self, LoadError> {
        let (file, arch, version) = ImageFile::new(path, arch, version)?;
        Ok(Self {
            arch,
            version,
            internal: ImageType::File(file),
        })
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn from_memory(
        name: &str,
        unload_fn: Option<LdrUnloadDll>,
        arch: Option<Arch>,
        version: Option<u32>,
    ) -> Result<Self, LoadError> {
        let (memory, arch, version) = ImageMemory::new(name, unload_fn, arch, version)?;
        Ok(Self {
            arch,
            version,
            internal: ImageType::Memory(memory),
        })
    }
}

#[derive(Clone)]
pub(crate) struct ImageHeaders<'a> {
    pub(crate) ptr: Ptr<'a, u8>,
    pub(crate) dos: &'a IMAGE_DOS_HEADER,
    pub(crate) file: &'a IMAGE_FILE_HEADER,
    pub(crate) opt: ArchData<&'a IMAGE_OPTIONAL_HEADER32, &'a IMAGE_OPTIONAL_HEADER64>,
    pub(crate) sections: &'a [IMAGE_SECTION_HEADER],
    pub(crate) directory: &'a [IMAGE_DATA_DIRECTORY],
}
impl<'a> ImageHeaders<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Result<Self, LoadError> {
        let ptr = Ptr::from(data);

        let dos = ptr
            .cast::<IMAGE_DOS_HEADER>()
            .as_ref()
            .ok_or(LoadError::InvalidDosHeader)?;
        if dos.e_magic != 0x5A4D {
            return Err(LoadError::InvalidDosHeader);
        }

        let sig = ptr.byte_add(dos.e_lfanew as usize).cast::<u32>().as_ref();
        if sig != Some(&0x00004550) {
            return Err(LoadError::InvalidNtHeaders);
        }

        let file = ptr
            .byte_add(dos.e_lfanew as usize)
            .byte_add(size_of::<u32>())
            .cast::<IMAGE_FILE_HEADER>()
            .as_ref()
            .ok_or(LoadError::InvalidNtHeaders)?;

        let opt_ptr = ptr
            .byte_add(dos.e_lfanew as usize)
            .byte_add(size_of::<u32>())
            .byte_add(size_of::<IMAGE_FILE_HEADER>());

        let magic = opt_ptr
            .cast::<u16>()
            .read()
            .ok_or(LoadError::InvalidPEFormat)?;

        let opt = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => ArchData::X86(
                opt_ptr
                    .cast::<IMAGE_OPTIONAL_HEADER32>()
                    .as_ref()
                    .ok_or(LoadError::InvalidPEFormat)?,
            ),
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => ArchData::X64(
                opt_ptr
                    .cast::<IMAGE_OPTIONAL_HEADER64>()
                    .as_ref()
                    .ok_or(LoadError::InvalidPEFormat)?,
            ),
            _ => return Err(LoadError::InvalidPEFormat),
        };
        match opt {
            ArchData::X86(opt) => {
                if opt.SizeOfImage <= opt.SizeOfHeaders {
                    return Err(LoadError::InvalidNtHeaders);
                }
            }
            ArchData::X64(opt) => {
                if opt.SizeOfImage <= opt.SizeOfHeaders {
                    return Err(LoadError::InvalidNtHeaders);
                }
            }
        }

        let directory = match opt {
            ArchData::X86(opt) => &opt.DataDirectory,
            ArchData::X64(opt) => &opt.DataDirectory,
        };

        let sections = ptr
            .byte_add(dos.e_lfanew as usize)
            .byte_add(size_of::<u32>())
            .byte_add(size_of::<IMAGE_FILE_HEADER>())
            .byte_add(file.SizeOfOptionalHeader as usize)
            .cast::<IMAGE_SECTION_HEADER>()
            .as_slice(file.NumberOfSections as usize)
            .ok_or(LoadError::InvalidSectionHeaders)?;

        Ok(Self {
            ptr,
            dos,
            file,
            opt,
            sections,
            directory,
        })
    }

    pub(crate) fn get_version(&self) -> Result<u32, LoadError> {
        let res_header = self.directory[IMAGE_DIRECTORY_ENTRY_RESOURCE as usize];
        let res_ptr = self
            .ptr
            .byte_add(res_header.VirtualAddress as usize)
            .truncate(res_header.Size as usize);

        let a = sig_search(res_ptr.cast(), VS_VERSION_SIG)
            .ok_or(LoadError::InvalidResourceDirectory)?;
        let b = sig_search(a, VS_FIXEDVERSION_SIG).ok_or(LoadError::InvalidResourceDirectory)?;
        let info = b
            .cast::<VS_FIXEDFILEINFO>()
            .as_ref()
            .ok_or(LoadError::InvalidResourceDirectory)?;

        Ok((info.dwFileVersionLS >> 16) as u32)
    }
}

#[derive(Clone)]
pub(crate) struct ExportIter<'a> {
    image: &'a Image,
    functions: &'a [u32],
    internal: core::iter::Zip<core::slice::Iter<'a, u32>, core::slice::Iter<'a, u16>>,
}
impl<'a> ExportIter<'a> {
    pub(crate) fn new(image: &'a Image) -> Result<Self, LoadError> {
        let headers = ImageHeaders::new(image.data())?;
        let ptr = Ptr::from(image.data());

        let entry = headers.directory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        let export = ptr
            .byte_add(entry.VirtualAddress as usize)
            .cast::<IMAGE_EXPORT_DIRECTORY>()
            .as_ref()
            .ok_or(LoadError::InvalidExportDirectory)?;

        let names = ptr
            .byte_add(export.AddressOfNames as usize)
            .cast::<u32>()
            .as_slice(export.NumberOfNames as usize)
            .ok_or(LoadError::InvalidExportNames)?;
        let functions = ptr
            .byte_add(export.AddressOfFunctions as usize)
            .cast::<u32>()
            .as_slice(export.NumberOfFunctions as usize)
            .ok_or(LoadError::InvalidExportFunctions)?;
        let ordinals = ptr
            .byte_add(export.AddressOfNameOrdinals as usize)
            .cast::<u16>()
            .as_slice(export.NumberOfNames as usize)
            .ok_or(LoadError::InvalidExportOrdinals)?;

        Ok(Self {
            image,
            functions,
            internal: names.iter().zip(ordinals.iter()),
        })
    }
}
impl<'a> Iterator for ExportIter<'a> {
    type Item = (&'a [u8], Ptr<'a, u8>);

    fn next(&mut self) -> Option<Self::Item> {
        let image = &self.image;
        let ptr = Ptr::from(image.data());

        for (&name_rva, &ordinal) in self.internal.by_ref() {
            let func_rva = match self.functions.get(ordinal as usize) {
                Some(&rva) => rva,
                None => continue,
            };
            if name_rva == 0 || func_rva == 0 {
                continue;
            }

            let name_ptr = ptr.byte_add(name_rva as usize).as_ref()?;
            let func_ptr = ptr.byte_add(func_rva as usize).as_ref()?;
            let name = unsafe { CStr::from_ptr(name_ptr as *const u8 as *const i8).to_bytes() };
            return Some((name, Ptr::new(func_ptr as *const u8, ptr.end())));
        }
        None
    }
}
