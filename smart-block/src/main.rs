use aya::maps::{Array, HashMap};
use aya::programs::{Xdp, XdpFlags};
use clap::{Parser, Subcommand};

use smart_block_common::{BlockStats, GroupKey};
use std::net::Ipv4Addr;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::collections::HashMap as StdHashMap;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "ens160")]
    iface: String,

    #[clap(subcommand)]
    command: Option<Command>,

    #[clap(long)]
    debug: bool,

    #[clap(long)]
    keep: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    Add {
        ip: Ipv4Addr,
    },
    Remove {
        ip: Ipv4Addr,
    },
    List,
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
}

#[derive(Debug, Subcommand)]
enum GroupCommand {
    Add {
        group_name: String,
        server_ip: Ipv4Addr,
        client_ip: Ipv4Addr,
    },
    Remove {
        group_name: String,
        server_ip: Ipv4Addr,
        client_ip: Ipv4Addr,
    },
    List,
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    if unsafe { libc::getuid() } != 0 {
        anyhow::bail!("Must run as root");
    }

    let pin_path_stats = "/sys/fs/bpf/smartblock_stats";
    let pin_path_global = "/sys/fs/bpf/smartblock_global";
    let pin_path_server_to_group = "/sys/fs/bpf/smartblock_server_to_group";
    let pin_path_group_blocks = "/sys/fs/bpf/smartblock_group_blocks";
    let pin_path_group_names = "/sys/fs/bpf/smartblock_group_names";

    // Handle CLI commands
    if let Some(cmd) = opt.command {
        match cmd {
            Command::Add { ip } => {
                let stats_data = aya::maps::MapData::from_pin(pin_path_stats)?;
                let mut stats_map: HashMap<_, u32, BlockStats> = HashMap::try_from(aya::maps::Map::from_map_data(stats_data)?)?;
                
                let global_data = aya::maps::MapData::from_pin(pin_path_global)?;
                let mut global_map: HashMap<_, u32, u32> = HashMap::try_from(aya::maps::Map::from_map_data(global_data)?)?;
                
                let key = u32::from(ip).to_be();
                if stats_map.get(&key, 0).is_err() {
                    stats_map.insert(key, BlockStats { pkts: 0, bytes: 0, last_seen: 0 }, 0)?;
                }
                global_map.insert(key, 1, 0)?;
                println!("Added {} to global blacklist", ip);
            }
            Command::Remove { ip } => {
                let global_data = aya::maps::MapData::from_pin(pin_path_global)?;
                let mut global_map: HashMap<_, u32, u32> = HashMap::try_from(aya::maps::Map::from_map_data(global_data)?)?;
                let key = u32::from(ip).to_be();
                global_map.remove(&key)?;
                println!("Removed {} from global blacklist", ip);
            }
            Command::List => {
                let stats_data = aya::maps::MapData::from_pin(pin_path_stats)?;
                let stats_map: HashMap<_, u32, BlockStats> = HashMap::try_from(aya::maps::Map::from_map_data(stats_data)?)?;
                let global_data = aya::maps::MapData::from_pin(pin_path_global)?;
                let global_map: HashMap<_, u32, u32> = HashMap::try_from(aya::maps::Map::from_map_data(global_data)?)?;
                
                println!("\n=== Global Blacklist ===");
                println!("{:<16} {:<10} {:<12} {:<20}", "IP Address", "Packets", "Data Size", "Last Seen");
                println!("{:-<65}", "");
                for result in global_map.iter() {
                    let (key, _) = result?;
                    if let Ok(stats) = stats_map.get(&key, 0) {
                        let ip = Ipv4Addr::from(u32::from_be(key));
                        println!("{:<16} {:<10} {:<12} {:<20}", ip, stats.pkts, format_size(stats.bytes), "N/A");
                    }
                }
            }
            Command::Group { command } => {
                match command {
                    GroupCommand::Add { group_name, server_ip, client_ip } => {
                        let group_id = get_group_id(&group_name);
                        
                        // Update SERVER_TO_GROUP
                        let s2g_data = aya::maps::MapData::from_pin(pin_path_server_to_group)?;
                        let mut s2g: HashMap<_, u32, u32> = HashMap::try_from(aya::maps::Map::from_map_data(s2g_data)?)?;
                        s2g.insert(u32::from(server_ip).to_be(), group_id, 0)?;

                        // Update GROUP_BLOCKS
                        let gb_data = aya::maps::MapData::from_pin(pin_path_group_blocks)?;
                        let mut gb: HashMap<_, GroupKey, u32> = HashMap::try_from(aya::maps::Map::from_map_data(gb_data)?)?;
                        let key = GroupKey { group_id, client_ip: u32::from(client_ip).to_be() };
                        gb.insert(key, 1, 0)?;

                        // Ensure IP is in STATS pool
                        let stats_data = aya::maps::MapData::from_pin(pin_path_stats)?;
                        let mut stats_map: HashMap<_, u32, BlockStats> = HashMap::try_from(aya::maps::Map::from_map_data(stats_data)?)?;
                        let client_key = u32::from(client_ip).to_be();
                        if stats_map.get(&client_key, 0).is_err() {
                            stats_map.insert(client_key, BlockStats { pkts: 0, bytes: 0, last_seen: 0 }, 0)?;
                        }

                        // Update GROUP_NAMES
                        let gn_data = aya::maps::MapData::from_pin(pin_path_group_names)?;
                        let mut gn_map: HashMap<_, u32, [u8; 32]> = HashMap::try_from(aya::maps::Map::from_map_data(gn_data)?)?;
                        let mut name_bytes = [0u8; 32];
                        let bytes = group_name.as_bytes();
                        let len = bytes.len().min(32);
                        name_bytes[..len].copy_from_slice(&bytes[..len]);
                        gn_map.insert(group_id, name_bytes, 0)?;

                        println!("Added {} to group '{}' (ID: {}) for server {}", client_ip, group_name, group_id, server_ip);
                    }
                    GroupCommand::Remove { group_name, server_ip: _, client_ip } => {
                        let group_id = get_group_id(&group_name);
                        let gb_data = aya::maps::MapData::from_pin(pin_path_group_blocks)?;
                        let mut gb: HashMap<_, GroupKey, u32> = HashMap::try_from(aya::maps::Map::from_map_data(gb_data)?)?;
                        let key = GroupKey { group_id, client_ip: u32::from(client_ip).to_be() };
                        gb.remove(&key)?;
                        println!("Removed {} from group '{}'", client_ip, group_name);
                    }
                    GroupCommand::List => {
                        let gb_data = aya::maps::MapData::from_pin(pin_path_group_blocks)?;
                        let gb_map: HashMap<_, GroupKey, u32> = HashMap::try_from(aya::maps::Map::from_map_data(gb_data)?)?;

                        let stats_data = aya::maps::MapData::from_pin(pin_path_stats)?;
                        let stats_map: HashMap<_, u32, BlockStats> = HashMap::try_from(aya::maps::Map::from_map_data(stats_data)?)?;

                        let gn_data = aya::maps::MapData::from_pin(pin_path_group_names)?;
                        let gn_map: HashMap<_, u32, [u8; 32]> = HashMap::try_from(aya::maps::Map::from_map_data(gn_data)?)?;

                        let s2g_data = aya::maps::MapData::from_pin(pin_path_server_to_group)?;
                        let s2g_map: HashMap<_, u32, u32> = HashMap::try_from(aya::maps::Map::from_map_data(s2g_data)?)?;

                        // Build a map of group_id to list of server IPs
                        let mut group_servers: StdHashMap<u32, Vec<Ipv4Addr>> = StdHashMap::new();
                        for result in s2g_map.iter() {
                            let (sip_be, gid) = result?;
                            group_servers.entry(gid).or_default().push(Ipv4Addr::from(u32::from_be(sip_be)));
                        }
                        println!("\n=== Group Blacklist ===");
                        println!("{:<15} {:<15} {:<30} {:<10} {:<12}", "IP Address", "Group Name", "Server IPs",  "Packets", "Data Size");
                        println!("{:-<90}", "");
                        
                        // Use Arc for shared IP objects to satisfy user memory optimization request
                        let mut ip_cache: StdHashMap<u32, Arc<Ipv4Addr>> = StdHashMap::new();

                        for result in gb_map.iter() {
                            let (key, _) = result?;
                            let name_bytes = gn_map.get(&key.group_id, 0).unwrap_or([0u8; 32]);
                            let group_name = String::from_utf8_lossy(&name_bytes).trim_matches('\0').to_string();
                            
                            let client_ip_arc = ip_cache.entry(key.client_ip).or_insert_with(|| {
                                Arc::new(Ipv4Addr::from(u32::from_be(key.client_ip)))
                            });

                            let servers = group_servers.get(&key.group_id).map(|v| {
                                v.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ")
                            }).unwrap_or_else(|| "N/A".to_string());

                            let stats = stats_map.get(&key.client_ip, 0).ok();
                            let pkts = stats.map(|s| s.pkts).unwrap_or(0);
                            let bytes = stats.map(|s| s.bytes).unwrap_or(0);

                            println!("{:<15} {:<15} {:<30} {:<10} {:<12}", client_ip_arc, group_name, servers, pkts, format_size(bytes));
                        }
                    }
                }
            }
        }
        return Ok(());
    }

    fn get_group_id(name: &str) -> u32 {
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        hasher.finish() as u32
    }

    fn format_size(bytes: u64) -> String {
        const KIB: u64 = 1024;
        const MIB: u64 = KIB * 1024;
        const GIB: u64 = MIB * 1024;

        if bytes >= GIB {
            format!("{:.2} GiB", bytes as f64 / GIB as f64)
        } else if bytes >= MIB {
            format!("{:.2} MiB", bytes as f64 / MIB as f64)
        } else if bytes >= KIB {
            format!("{:.2} KiB", bytes as f64 / KIB as f64)
        } else {
            format!("{} B", bytes)
        }
    }

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        println!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/smart-block"
    )))?;

    let Opt { iface, .. } = opt;
    let program: &mut Xdp = ebpf.program_mut("smart_block").unwrap().try_into()?;
    program.load()?;

    let mode = match program.attach(&iface, XdpFlags::DRV_MODE) {
        Ok(_) => "Native (DRV)",
        Err(e) => {
            log::warn!(
                "Failed to attach in Native (DRV) mode: {}. Switching to Generic (SKB) mode...",
                e
            );
            program.attach(&iface, XdpFlags::SKB_MODE)?;
            "Generic (SKB)"
        }
    };

    let pin_maps = [
        ("BLOCK_STATS", pin_path_stats),
        ("GLOBAL_BLOCKS", pin_path_global),
        ("SERVER_TO_GROUP", pin_path_server_to_group),
        ("GROUP_BLOCKS", pin_path_group_blocks),
        ("GROUP_NAMES", pin_path_group_names),
    ];

    for (map_name, pin_path) in &pin_maps {
        let path = std::path::Path::new(pin_path);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        ebpf.map_mut(map_name).unwrap().pin(path)?;
    }

    // Set debug mode in CONFIG map
    let mut config: Array<_, u32> = Array::try_from(ebpf.map_mut("CONFIG").unwrap())?;
    config.set(0, if opt.debug { 1 } else { 0 }, 0)?;

    println!("SmartBlock (Interface: {}, Mode: {})...", iface, mode);
    println!("* Maps pinned at: /sys/fs/bpf/smartblock_*");
    if opt.debug {
        println!("!! Debug mode enabled. Please check logs via: sudo cat /sys/kernel/debug/tracing/trace_pipe");
    }

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        _ = sigint.recv() => println!("Stopping (SIGINT)..."),
        _ = sigterm.recv() => println!("Stopping (SIGTERM)..."),
    }

    if !opt.keep {
        for (_, path) in &pin_maps {
            if std::path::Path::new(path).exists() {
                std::fs::remove_file(path)?;
            }
        }
        println!("* Removed Maps pinned at: /sys/fs/bpf/smartblock_*");
    } else {
        println!("* Maps kept at: /sys/fs/bpf/smartblock_*");
    }

    Ok(())
}
