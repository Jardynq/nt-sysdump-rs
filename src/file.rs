use crate::LoadError;
use crate::image::{Arch, ArchData, ImageHeaders};
use std::io::Read;

#[derive(Clone)]
pub(crate) struct ImageFile {
    data: Vec<u8>,
}
impl ImageFile {
    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }
    pub(crate) fn new(
        path: &str,
        arch: Option<Arch>,
        version: Option<u32>,
    ) -> Result<(Self, Arch, u32), LoadError> {
        let src = {
            let len = std::fs::metadata(path).map_err(LoadError::IoError)?.len();
            let mut buf = Vec::with_capacity(len as usize);
            let mut file = std::fs::File::open(path).map_err(LoadError::IoError)?;
            file.read_to_end(&mut buf).map_err(LoadError::IoError)?;
            buf
        };

        let headers = ImageHeaders::new(&src)?;

        // Create buffer for properly aligned image
        let (mut dst, header_size) = match headers.opt {
            ArchData::X86(opt) => (
                vec![0; opt.SizeOfImage as usize],
                opt.SizeOfHeaders as usize,
            ),
            ArchData::X64(opt) => (
                vec![0; opt.SizeOfImage as usize],
                opt.SizeOfHeaders as usize,
            ),
        };

        // Copy headers
        dst[0..header_size].copy_from_slice(&src[0..header_size]);

        // Copy sections
        for section in headers.sections {
            let src_start = section.PointerToRawData as usize;
            let src_end = src_start
                .checked_add(section.SizeOfRawData as usize)
                .ok_or(LoadError::InvalidSection)?;
            if src_end > src.len() {
                return Err(LoadError::InvalidSection);
            }

            let virt_start = section.VirtualAddress as usize;
            let virt_end = virt_start
                .checked_add(section.SizeOfRawData as usize)
                .ok_or(LoadError::InvalidSection)?;
            if virt_end > dst.len() {
                return Err(LoadError::InvalidSection);
            }

            let src_bytes = src
                .get(src_start..src_end)
                .ok_or(LoadError::InvalidSection)?;
            let dest_bytes = dst
                .get_mut(virt_start..virt_end)
                .ok_or(LoadError::InvalidSection)?;

            dest_bytes.copy_from_slice(src_bytes);
        }

        let version = match version {
            Some(version) => version,
            None => ImageHeaders::new(&dst)?.get_version()?,
        };
        let arch = match arch {
            Some(arch) => arch,
            None => match &headers.opt {
                ArchData::X86(_) => Arch::X86,
                ArchData::X64(_) => Arch::X64,
            },
        };
        Ok((Self { data: dst }, arch, version))
    }
}
