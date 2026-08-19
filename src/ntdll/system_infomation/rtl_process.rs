use std::ffi::c_void;

// 오프셋 계산 방지
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RtlProcessModuleInformation {
    pub section: *mut c_void,
    pub mapped_base: *mut c_void,
    pub image_base: *mut c_void,

    pub image_size: u32,
    pub flags: u32,

    pub load_order_index: u16,
    pub init_order_index: u16,
    pub load_count: u16,
    pub offset_to_file_name: u16,

    pub full_path_name: [u8; 256],
}

#[repr(C)]
pub struct RtlProcessModules {
    pub number_of_modules: u32,

    // 실제로는 number_of_modules개가 연속해서 존재
    pub modules: [RtlProcessModuleInformation; 0],
}