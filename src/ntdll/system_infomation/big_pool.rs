//계산 방지용
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SystemBigPoolEntry {
    // 최하위 1bit는 NonPaged 여부로 사용됨
    pub virtual_address_and_flags: usize,
    pub size_in_bytes: usize,
    pub tag: [u8; 4],
}

impl SystemBigPoolEntry {
    pub fn virtual_address(&self) -> usize {
        self.virtual_address_and_flags & !1usize
    }
    pub fn is_non_paged(&self) -> bool {
        self.virtual_address_and_flags & 1 != 0
    }
    pub fn tag(&self) -> &[u8; 4] {
        &self.tag
    }
}

#[repr(C)]
pub struct SystemBigPoolInformation {
    pub count: u32,
    pub entries: [SystemBigPoolEntry; 0],
}