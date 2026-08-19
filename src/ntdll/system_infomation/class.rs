#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemInformationClass {
    SystemModuleInformation = 11,
    SystemHandleInformation = 16,
    SystemExtendedHandleInformation = 64,
    SystemBigPoolInformation = 66,
}