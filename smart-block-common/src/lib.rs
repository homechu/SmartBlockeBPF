#![no_std]

pub const ACTION_DROP: u32 = 0;
pub const ACTION_TARPIT: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockStats {
    pub pkts: u64,
    pub bytes: u64,
    pub last_seen: u64,
    pub action: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GroupKey {
    pub group_id: u32,
    pub client_ip: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockStats {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for GroupKey {}
