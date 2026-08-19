use std::ffi::c_void;

use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_INFO_LENGTH_MISMATCH};

use crate::ntdll::{extern_raw::NtQuerySystemInformation, system_infomation::class::SystemInformationClass};

pub fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NtHelperError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid input: {0}")]
    RepeatError(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// pub fn nt_system_extended_handle_information() -> Result<Vec<u32>, NtHelperError> {

// }

pub fn nt_system_big_pool_infomation_helper() -> Result<Vec<u32>, NtHelperError> {
    let info_class =  SystemInformationClass::SystemBigPoolInformation;
    let err_msg = "repeat_nt_system_big_pool_infomation_helper_error".to_string();

    let mut buffer_size: u32 = 0;
    let mut info_buffer:Vec<u32> = Vec::new();

    info_buffer.resize(0x100, 0);
    let break_cnt = 0;

    loop{
        if break_cnt >= 100 {
            return Err(NtHelperError::RepeatError(err_msg))
        }

        let status: NTSTATUS = unsafe {
                NtQuerySystemInformation(
                info_class,
                info_buffer.as_mut_ptr().cast::<c_void>(),
                buffer_size,
                &mut buffer_size,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            info_buffer.resize((buffer_size + 0x100) as usize, 0);
            continue;
        }
        break;
    }

    Ok(info_buffer)
}
