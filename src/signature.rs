use crate::Ptr;

pub(crate) enum SigByte {
    Byte(&'static [u8]),
    Target,
    Ignore,
}

pub(crate) const fn hex_from_str(mut hex: &str) -> u8 {
    let bytes = hex.as_bytes();
    if bytes.len() > 2 {
        if bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
            let (_, rest) = hex.split_at(1);
            (hex, _) = rest.split_at(rest.len() - 1);
        }
        if bytes[0] == b'0' && bytes[1] == b'x' {
            (_, hex) = hex.split_at(2);
        }
    }
    match u8::from_str_radix(hex, 16) {
        Ok(v) => v,
        Err(_) => panic!("{}", hex),
    }
}

macro_rules! sig {
    (@parse ?) => { $crate::signature::SigByte::Ignore };
    (@parse x) => { $crate::signature::SigByte::Target };

    (@parse [ $($val:tt)+ ]) => {
        $crate::signature::SigByte::Byte(&[
            $($crate::signature::hex_from_str(stringify!($val))),+
        ])
    };
    (@parse [ $($val:tt)+ ]) => {
        $crate::signature::SigByte::Byte(&[
            $($crate::signature::hex_from_str(stringify!($val))),+
        ])
    };
    (@parse $val:tt) => {{
        $crate::signature::SigByte::Byte(&[
            $crate::signature::hex_from_str(stringify!($val))
        ])
    }};

    ($($tok:tt)+) => {
        &[
            $(sig!(@parse $tok)),+
        ]
    };
}
pub(crate) use sig;

macro_rules! sig_wide {
    ($($c:literal),* $(,)?) => {
        &[
            $(
                $crate::signature::SigByte::Byte(&[$c as char as u8]),
                $crate::signature::SigByte::Byte(&[0]),
            )*
        ]
    };
}
pub(crate) use sig_wide;

pub(crate) struct SigExtractIter<'a> {
    ptr: Ptr<'a, u8>,
    signature: &'a [SigByte],
    index: usize,
}
impl<'a> SigExtractIter<'a> {
    pub(crate) unsafe fn new(ptr: Ptr<'a, u8>, signature: &'a [SigByte]) -> Option<Self> {
        if !sig_match(ptr, signature) {
            return None;
        }
        Some(Self {
            ptr,
            signature,
            index: 0,
        })
    }
}
impl<'a> Iterator for SigExtractIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.signature.len() {
            return None;
        }
        self.index += 1;
        match &self.signature[self.index] {
            SigByte::Target => self.ptr.byte_add(self.index).read(),
            _ => self.next(),
        }
    }
}

pub(crate) fn sig_match(mut ptr: Ptr<u8>, signature: &[SigByte]) -> bool {
    for byte in signature {
        let val = match ptr.read() {
            Some(v) => v,
            None => return false,
        };
        if let SigByte::Byte(values) = byte
            && values.iter().all(|value| *value != val)
        {
            return false;
        }
        ptr = ptr.byte_add(1);
    }
    true
}
pub(crate) fn sig_search<'a>(mut ptr: Ptr<'a, u8>, signature: &[SigByte]) -> Option<Ptr<'a, u8>> {
    while ptr.is_valid() {
        if sig_match(ptr, signature) {
            return Some(ptr);
        }
        ptr = ptr.byte_add(1);
    }
    None
}

pub(crate) fn sig_extract_u64(ptr: Ptr<u8>, signature: &[SigByte]) -> Option<u64> {
    let mut result = unsafe { SigExtractIter::new(ptr, signature)? };
    let r0 = result.next()? as u64;
    let r1 = (result.next()? as u64) << 8;
    let r2 = (result.next()? as u64) << 16;
    let r3 = (result.next()? as u64) << 24;
    let r4 = (result.next()? as u64) << 32;
    let r5 = (result.next()? as u64) << 40;
    let r6 = (result.next()? as u64) << 48;
    let r7 = (result.next()? as u64) << 56;
    Some(r0 + r1 + r2 + r3 + r4 + r5 + r6 + r7)
}
pub(crate) fn sig_extract_u32(ptr: Ptr<u8>, signature: &[SigByte]) -> Option<u32> {
    let mut result = unsafe { SigExtractIter::new(ptr, signature)? };
    let r0 = result.next()? as u32;
    let r1 = (result.next()? as u32) << 8;
    let r2 = (result.next()? as u32) << 16;
    let r3 = (result.next()? as u32) << 24;
    Some(r0 + r1 + r2 + r3)
}
pub(crate) fn sig_extract_u16(ptr: Ptr<u8>, signature: &[SigByte]) -> Option<u16> {
    let mut result = unsafe { SigExtractIter::new(ptr, signature)? };
    let r0 = result.next()? as u16;
    let r1 = (result.next()? as u16) << 8;
    Some(r0 + r1)
}
pub(crate) fn sig_extract_u8(ptr: Ptr<u8>, signature: &[SigByte]) -> Option<u8> {
    unsafe { SigExtractIter::new(ptr, signature)?.next() }
}
