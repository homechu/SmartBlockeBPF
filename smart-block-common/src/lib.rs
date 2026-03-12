#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BlockStats {
    pub pkts: u64,
    pub bytes: u64,
    pub last_seen: u64,
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
