use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;

use std::io::{Seek, SeekFrom, Write};


pub fn append(base: &OsStr, suffix: &str) -> OsString {
    let mut result = base.to_os_string();
    result.push(suffix);
    result
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

pub fn osstr_wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide()
        .chain(std::iter::once(0))
        .collect()
}


pub fn patch(file: &mut std::fs::File, offset: u64, data: &[u8]) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(data)?;
    Ok(())
}