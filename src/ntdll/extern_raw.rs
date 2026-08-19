use std::os::windows::raw::HANDLE;
use std::ffi::c_void;
use windows_sys::Wdk::Storage::FileSystem::FILE_INFORMATION_CLASS;
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use crate::ntdll::system_infomation::class::SystemInformationClass;


#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtQuerySystemInformation(
        system_information_class: SystemInformationClass,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtSetInformationFile(
        file_handle: HANDLE,
        io_status_block: *mut IO_STATUS_BLOCK,
        file_information: *const c_void,
        length: u32,
        file_information_class: FILE_INFORMATION_CLASS,
    ) -> NTSTATUS;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtFsControlFile(
        file_handle: HANDLE,
        event: HANDLE,
        apc_routine: *mut c_void,
        apc_context: *mut c_void,
        io_status_block: *mut IO_STATUS_BLOCK,
        fs_control_code: u32,
        input_buffer: *mut c_void,
        input_buffer_length: u32,
        output_buffer: *mut c_void,
        output_buffer_length: u32,
    ) -> NTSTATUS;
}