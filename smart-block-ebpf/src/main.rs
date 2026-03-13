#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_ktime_get_ns, bpf_printk},
    macros::{map, xdp},
    maps::{Array, HashMap, LpmTrie},
    programs::XdpContext,
};
use aya_ebpf::bindings::BPF_F_NO_PREALLOC;
use core::mem;
use network_types::{
    eth::{EthHdr},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};
use smart_block_common::{BlockStats, GroupKey};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PPv2Info {
    pub client_ip: u32,
    pub client_port: u16,
    pub server_ip: u32,
    pub server_port: u16,
}

#[map]
static BLOCK_STATS: HashMap<u32, BlockStats> = HashMap::with_max_entries(8192, 0);

#[map]
static CIDR_BLOCKS: LpmTrie<u32, u32> = LpmTrie::with_max_entries(1024, BPF_F_NO_PREALLOC);

#[map]
static DROP_STATS: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static SERVER_TO_GROUP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static GROUP_BLOCKS: HashMap<GroupKey, u32> = HashMap::with_max_entries(4096, 0);

#[map]
static GROUP_NAMES: HashMap<u32, [u8; 32]> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn smart_block(ctx: XdpContext) -> u32 {
    match try_smart_block(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn get_proxied_ip_v2(start: usize, end: usize) -> Option<PPv2Info> {
    if start + 28 > end {
        return None;
    }

    let p = start as *const u8;
    unsafe {
        if *p != 0x0D
            || *p.add(1) != 0x0A
            || *p.add(2) != 0x0D
            || *p.add(3) != 0x0A
            || *p.add(4) != 0x00
            || *p.add(5) != 0x0D
            || *p.add(6) != 0x0A
            || *p.add(7) != 0x51
            || *p.add(8) != 0x55
            || *p.add(9) != 0x49
            || *p.add(10) != 0x54
            || *p.add(11) != 0x0A
        {
            return None;
        }

        let ver_cmd = *p.add(12);
        if (ver_cmd & 0xF0) != 0x20 {
            return None;
        }

        let fam_proto = *p.add(13);
        if (fam_proto & 0xF0) != 0x10 {
            return None;
        }

        let src_ip = core::ptr::read_unaligned(p.add(16) as *const u32);
        let dst_ip = core::ptr::read_unaligned(p.add(20) as *const u32);
        let src_port = core::ptr::read_unaligned(p.add(24) as *const u16);
        let dst_port = core::ptr::read_unaligned(p.add(26) as *const u16);

        Some(PPv2Info {
            client_ip: src_ip,
            client_port: u16::from_be(src_port),
            server_ip: dst_ip,
            server_port: u16::from_be(dst_port),
        })
    }
}

#[inline(always)]
fn get_proxied_ip_v1(start: usize, end: usize) -> Option<u32> {
    if start + 24 > end {
        return None;
    }

    let p = start as *const u8;
    unsafe {
        if *p != b'P' || *p.add(1) != b'R' || *p.add(2) != b'O' || *p.add(3) != b'X' || *p.add(4) != b'Y' {
            return None;
        }
    }

    let mut res: u32 = 0;
    let mut octet: u32 = 0;
    let mut dots = 0;
    
    for i in 11..26 {
        let current_ptr = (start + i) as *const u8;
        if (current_ptr as usize) + 1 > end {
            break;
        }
        
        let c = unsafe { *current_ptr };
        if c >= b'0' && c <= b'9' {
            octet = octet * 10 + (c - b'0') as u32;
        } else if c == b'.' {
            res = (res << 8) | (octet & 0xFF);
            octet = 0;
            dots += 1;
        } else if c == b' ' {
            if dots == 3 {
                res = (res << 8) | (octet & 0xFF);
                return Some(u32::from_be(res));
            }
            return None;
        } else {
            return None;
        }
    }
    None
}

fn try_smart_block(ctx: XdpContext) -> Result<u32, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let pkt_len = (end - start) as u64;

    let eth_hdr_ptr: *const EthHdr = start as *const EthHdr;
    if (start + mem::size_of::<EthHdr>()) > end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_type = u16::from_be(unsafe { (*eth_hdr_ptr).ether_type as u16 });
    if eth_type != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr_start = start + mem::size_of::<EthHdr>();
    if ip_hdr_start + mem::size_of::<Ipv4Hdr>() > end {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip_hdr = ip_hdr_start as *const Ipv4Hdr;
    let src_addr = unsafe { (*ip_hdr).src_addr };

    let debug_enabled = if let Some(val) = CONFIG.get(0) {
        *val == 1
    } else {
        false
    };

    if debug_enabled {
        let ip = u32::from_be(src_addr);
        let o1 = (ip >> 24) & 0xFF;
        let o2 = (ip >> 16) & 0xFF;
        let o3 = (ip >> 8) & 0xFF;
        let o4 = ip & 0xFF;

        unsafe { 
            bpf_printk!(b"SRC: %u.%u.", o1, o2);
            bpf_printk!(b"     %u.%u", o3, o4); 
        };
    }

    let lpm_key = aya_ebpf::maps::lpm_trie::Key { prefix_len: 32, data: src_addr };
    if let Some(base_ip) = CIDR_BLOCKS.get(&lpm_key) {
        if let Some(stats) = BLOCK_STATS.get_ptr_mut(base_ip) {
            update_stats(stats, pkt_len);
        } 
        return drop_packet();
    }

    if unsafe { (*ip_hdr).proto } == IpProto::Tcp {
        let ip_v_ihl = unsafe { *(ip_hdr_start as *const u8) };
        let ip_len = ((ip_v_ihl & 0x0F) as usize) * 4;
        
        if ip_len < 20 || ip_len > 60 {
            return Ok(xdp_action::XDP_PASS);
        }

        let tcp_hdr_start = ip_hdr_start + ip_len;
        if tcp_hdr_start + mem::size_of::<TcpHdr>() > end {
            return Ok(xdp_action::XDP_PASS);
        }
        
        let _tcp_hdr = tcp_hdr_start as *const TcpHdr;
        let data_offset = unsafe { (*(tcp_hdr_start as *const u8).add(12) >> 4) as usize } * 4;

        if data_offset < 20 || data_offset > 60 {
            return Ok(xdp_action::XDP_PASS);
        }

        let payload_start = tcp_hdr_start + data_offset;
        
        if payload_start + 28 <= end {
            if let Some(info) = get_proxied_ip_v2(payload_start, end) {
                let proxied_ip = info.client_ip;
                if debug_enabled {
                    let pip = u32::from_be(proxied_ip);
                    let p1 = (pip >> 24) & 0xFF;
                    let p2 = (pip >> 16) & 0xFF;
                    let p3 = (pip >> 8) & 0xFF;
                    let p4 = pip & 0xFF;
                    unsafe { 
                        bpf_printk!(b"V2:  %u.%u.", p1, p2);
                        bpf_printk!(b"     %u.%u", p3, p4); 
                    };
                }

                let p_lpm_key = aya_ebpf::maps::lpm_trie::Key { prefix_len: 32, data: proxied_ip };
                if let Some(base_ip) = CIDR_BLOCKS.get(&p_lpm_key) {
                    if let Some(stats) = BLOCK_STATS.get_ptr_mut(base_ip) {
                        update_stats(stats, pkt_len);
                    }
                    return drop_packet();
                }

                if let Some(group_id) = unsafe { SERVER_TO_GROUP.get(&info.server_ip) } {
                    let key = GroupKey {
                        group_id: *group_id,
                        client_ip: proxied_ip,
                    };
                    if unsafe { GROUP_BLOCKS.get(&key).is_some() } {
                        if let Some(stats) = BLOCK_STATS.get_ptr_mut(&proxied_ip) {
                            update_stats(stats, pkt_len);
                        }
                        return drop_packet();
                    }
                }
            } else if let Some(proxied_ip) = get_proxied_ip_v1(payload_start, end) {
                if debug_enabled {
                    let pip = u32::from_be(proxied_ip);
                    let p1 = (pip >> 24) & 0xFF;
                    let p2 = (pip >> 16) & 0xFF;
                    let p3 = (pip >> 8) & 0xFF;
                    let p4 = pip & 0xFF;
                    unsafe { 
                        bpf_printk!(b"V1:  %u.%u.", p1, p2);
                        bpf_printk!(b"     %u.%u", p3, p4); 
                    };
                }

                let p_lpm_key = aya_ebpf::maps::lpm_trie::Key { prefix_len: 32, data: proxied_ip };
                if let Some(base_ip) = CIDR_BLOCKS.get(&p_lpm_key) {
                    if let Some(stats) = BLOCK_STATS.get_ptr_mut(base_ip) {
                        update_stats(stats, pkt_len);
                    }
                    return drop_packet();
                }
            }
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn update_stats(stats: *mut BlockStats, len: u64) {
    unsafe {
        (*stats).pkts += 1;
        (*stats).bytes += len;
        (*stats).last_seen = bpf_ktime_get_ns();
    }
}

#[inline(always)]
fn drop_packet() -> Result<u32, u32> {
    if let Some(ptr) = DROP_STATS.get_ptr_mut(0) {
        unsafe {
            core::ptr::write_volatile(ptr, *ptr + 1);
        }
    }
    Ok(xdp_action::XDP_DROP)
}

#[cfg(all(not(test), target_arch = "bpf"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
