use std::ffi::c_void;

use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_INFO_LENGTH_MISMATCH};

use crate::{helper::nt_helper, ntdll::{extern_raw::NtQuerySystemInformation, system_infomation::class::SystemInformationClass}};

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

pub fn nt_system_extended_handle_information() -> Result<Vec<u8>, NtHelperError> {
    let info_class =  SystemInformationClass::SystemExtendedHandleInformation;
    let err_msg = "repeat_nt_system_big_pool_infomation_helper_error".to_string();

    let mut buffer: Vec<u8> = Vec::new();
    buffer.resize(0x1000, 0);
    let mut return_length = 0u32;
    loop {
        let status = unsafe {
            NtQuerySystemInformation(
                info_class,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut return_length,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH {
            buffer.resize(return_length as usize, 0);
            continue;
        }

        if !nt_helper::nt_success(status) {
            return Err(NtHelperError::RepeatError(err_msg))
            
        }

        break;
    }
    return Ok(buffer)
}

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
