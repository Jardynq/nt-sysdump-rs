#![cfg_attr(feature = "no_std", no_std)]
#![allow(dead_code)]

#[cfg(all(feature = "no_std", not(windows)))]
compile_error!("`no_std` is only supported on Windows");

#[cfg(feature = "no_std")]
extern crate alloc;
#[cfg(feature = "no_std")]
use alloc::{string::String, vec::Vec};

#[cfg(not(feature = "no_std"))]
mod file;
#[cfg(windows)]
mod memory;

use core::marker::PhantomData;
use core::slice;

mod image;
mod images;
mod signature;

pub use image::Arch;

#[derive(Clone, Copy, PartialEq)]
pub enum LoadFile {
    Ntdll,    // Nt syscalls from user mode dll
    Ntoskrnl, // Nt syscalls from kernel module
    Win32u,   // User32 syscalls from user mode dll
    Win32k,   // User32 syscalls from kernel module
    Wow64win, // Nt and User32 syscalls from user mode dll
}

#[derive(Clone, Copy, PartialEq)]
pub enum LoadMethod {
    Sorting,
    Assembly,
}

pub enum LoadSource {
    #[cfg(windows)]
    Memory,
    #[cfg(not(feature = "no_std"))]
    File(String),
}

#[derive(Debug)]
pub enum LoadError {
    #[cfg(not(feature = "no_std"))]
    IoError(std::io::Error),

    ImageNotFound,
    UnsupportedArchitecture(Arch),
    UnsupportedVersion(u32),
    UnsupportedMethod,
    LoaderTableNotFound,
    InvalidPEFormat,
    InvalidDosHeader,
    InvalidNtHeaders,
    InvalidSectionHeaders,
    InvalidSection,
    InvalidExportDirectory,
    InvalidExportNames,
    InvalidExportOrdinals,
    InvalidExportFunctions,
    InvalidResourceDirectory,
}
impl core::fmt::Display for LoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LoadError::ImageNotFound => write!(f, "Image not found"),
            LoadError::UnsupportedArchitecture(arch) => {
                write!(f, "Unsupported architecture: {}", arch)
            }
            LoadError::UnsupportedVersion(version) => {
                write!(f, "Unsupported version: {}", version)
            }
            LoadError::UnsupportedMethod => write!(f, "Unsupported method"),
            LoadError::LoaderTableNotFound => write!(f, "Loader table not found"),
            LoadError::InvalidPEFormat => write!(f, "Invalid PE format"),
            LoadError::InvalidDosHeader => write!(f, "Invalid DOS header"),
            LoadError::InvalidNtHeaders => write!(f, "Invalid NT headers"),
            LoadError::InvalidSectionHeaders => write!(f, "Invalid section headers"),
            LoadError::InvalidSection => write!(f, "Invalid section"),
            LoadError::InvalidExportDirectory => write!(f, "Invalid export directory"),
            LoadError::InvalidExportNames => write!(f, "Invalid export names"),
            LoadError::InvalidExportOrdinals => write!(f, "Invalid export ordinals"),
            LoadError::InvalidExportFunctions => write!(f, "Invalid export functions"),
            LoadError::InvalidResourceDirectory => write!(f, "Invalid resource directory"),
            #[cfg(not(feature = "no_std"))]
            LoadError::IoError(e) => write!(f, "File IO error: {}", e),
        }
    }
}
impl From<LoadError> for String {
    fn from(e: LoadError) -> Self {
        e.to_string()
    }
}

#[allow(unused_variables)]
pub fn dump(
    file: LoadFile,
    method: LoadMethod,
    from: LoadSource,
    arch: Option<Arch>,
    version: Option<u32>,
) -> Result<Vec<(String, u32)>, LoadError> {
    match from {
        #[cfg(windows)]
        LoadSource::Memory => match (file, method) {
            (LoadFile::Ntdll, LoadMethod::Sorting) => {
                images::ntdll::from_memory(LoadMethod::Sorting, arch, version)
            }
            (LoadFile::Ntdll, LoadMethod::Assembly) => {
                images::ntdll::from_memory(LoadMethod::Assembly, arch, version)
            }
            (LoadFile::Win32u, LoadMethod::Sorting) => {
                images::win32u::from_memory(LoadMethod::Sorting, arch, version)
            }
            (LoadFile::Win32u, LoadMethod::Assembly) => {
                images::win32u::from_memory(LoadMethod::Assembly, arch, version)
            }
            _ => unimplemented!(),
        },
        #[cfg(not(feature = "no_std"))]
        LoadSource::File(path) => match (file, method) {
            (LoadFile::Ntdll, LoadMethod::Sorting) => {
                images::ntdll::from_file(&path, LoadMethod::Sorting, arch, version)
            }
            (LoadFile::Ntdll, LoadMethod::Assembly) => {
                images::ntdll::from_file(&path, LoadMethod::Assembly, arch, version)
            }
            (LoadFile::Win32u, LoadMethod::Sorting) => {
                images::win32u::from_file(&path, LoadMethod::Sorting, arch, version)
            }
            (LoadFile::Win32u, LoadMethod::Assembly) => {
                images::win32u::from_file(&path, LoadMethod::Assembly, arch, version)
            }
            _ => unimplemented!(),
        },
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Ptr<'a, T> {
    start: *const T,
    end: *const T,
    ptr: *const T,
    _marker: PhantomData<&'a ()>,
}
impl<'a, T> From<&'a [T]> for Ptr<'a, T> {
    fn from(slice: &'a [T]) -> Self {
        let range = slice.as_ptr_range();
        Self {
            start: range.start,
            end: range.end,
            ptr: range.start,
            _marker: PhantomData,
        }
    }
}

impl<'a, T> Ptr<'a, T> {
    pub(crate) fn new(start: *const T, end: *const T) -> Self {
        Self {
            start,
            end,
            ptr: start,
            _marker: PhantomData,
        }
    }
    pub(crate) fn new_sized(start: *const T, size: usize) -> Self {
        Self {
            start,
            end: unsafe { start.byte_add(size) },
            ptr: start,
            _marker: PhantomData,
        }
    }
    pub(crate) fn start(&self) -> *const T {
        self.start
    }
    pub(crate) fn end(&self) -> *const T {
        self.end
    }
    pub(crate) fn ptr(&self) -> *const T {
        self.ptr
    }
    pub(crate) fn is_valid(&self) -> bool {
        !self.ptr.is_null() && self.ptr >= self.start && unsafe { self.ptr.add(1) } < self.end
    }
    pub(crate) fn truncate(self, len: usize) -> Self {
        let new_end = unsafe { self.ptr.byte_add(len) };
        if new_end > self.end {
            return self;
        }
        Self {
            start: self.start,
            end: new_end,
            ptr: self.ptr,
            _marker: PhantomData,
        }
    }
    pub(crate) fn add(self, count: usize) -> Self {
        Self {
            start: self.start,
            end: self.end,
            ptr: unsafe { self.ptr.add(count) },
            _marker: PhantomData,
        }
    }
    pub(crate) fn byte_add(self, count: usize) -> Self {
        Self {
            start: self.start,
            end: self.end,
            ptr: unsafe { self.ptr.byte_add(count) },
            _marker: PhantomData,
        }
    }
    pub(crate) fn read(&self) -> Option<T> {
        if !self.is_valid() {
            return None;
        }
        unsafe { Some(self.ptr.read()) }
    }
    pub(crate) fn as_ref(&self) -> Option<&'a T> {
        if !self.is_valid() {
            return None;
        }
        unsafe { Some(&*self.ptr) }
    }
    pub(crate) fn cast<U>(self) -> Ptr<'a, U> {
        Ptr {
            start: self.start as *const U,
            end: self.end as *const U,
            ptr: self.ptr as *const U,
            _marker: PhantomData,
        }
    }
    pub(crate) fn as_slice(&self, count: usize) -> Option<&'a [T]> {
        let is_bounded = self.ptr >= self.start && unsafe { self.ptr.add(count) < self.end };
        if self.ptr.is_null() || !is_bounded {
            return None;
        }
        unsafe { Some(slice::from_raw_parts(self.ptr, count)) }
    }
}
