use std::ffi::c_void;

#[repr(C)]
pub struct ListEntry {
    pub flink: *mut c_void,
    pub blink: *mut c_void,
}

#[repr(C)]
pub struct PipeAttribute {
    pub list: ListEntry,                  // +0x00
    pub attribute_name: *mut c_void,      // +0x10
    pub attribute_value_size: u64,        // +0x18
    pub attribute_value: *mut c_void,     // +0x20
}
