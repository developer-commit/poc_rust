use std::ffi::c_void;

// 계산 방지용
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SystemHandleTableEntryInfoEx {
    pub object: *mut c_void,
    pub unique_process_id: usize,
    pub handle_value: usize,
    pub granted_access: u32,
    pub creator_back_trace_index: u16,
    pub object_type_index: u16,
    pub handle_attributes: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SystemHandleInformationEx {
    pub number_of_handles: usize,
    pub reserved: usize,
    pub handles: [SystemHandleTableEntryInfoEx; 0],
}

// 계산 방지용
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SystemHandleTableEntryInfo {
    pub unique_process_id: u16,
    pub creator_back_trace_index: u16,
    pub object_type_index: u8,
    pub handle_attributes: u8,
    pub handle_value: u16,
    pub object: *mut c_void,
    pub granted_access: u32,
}

#[repr(C)]
pub struct SystemHandleInformation {
    pub number_of_handles: u32,

    // 실제로는 number_of_handles개가 뒤에 연속해서 존재
    pub handles: [SystemHandleTableEntryInfo; 0],
}