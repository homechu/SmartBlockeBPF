use aya::maps::{Array, HashMap, LpmTrie};
use aya::programs::{Xdp, XdpFlags};
use clap::{Parser, Subcommand};

use smart_block_common::{BlockStats, GroupKey, ACTION_DROP, ACTION_TARPIT};
use std::net::Ipv4Addr;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::collections::HashMap as StdHashMap;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ActionArg {
    Drop,
    Tarpit,
}

impl From<ActionArg> for u32 {
    fn from(arg: ActionArg) -> Self {
        match arg {
            ActionArg::Drop => ACTION_DROP,
            ActionArg::Tarpit => ACTION_TARPIT,
        }
    }
}

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
        #[clap(help = "IP address or CIDR range (e.g. 1.2.3.4 or 1.2.3.0/24)")]
        target: String,

        #[clap(long, value_enum, default_value = "drop", help = "Action for matched packets: drop or tarpit")]
        action: ActionArg,
    },
    Remove {
        #[clap(help = "IP address or CIDR range (e.g. 1.2.3.4 or 1.2.3.0/24)")]
        target: String,
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

        #[clap(long, value_enum, default_value = "drop", help = "Action for matched packets: drop or tarpit")]
        action: ActionArg,
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
    let pin_path_cidr = "/sys/fs/bpf/smartblock_cidr";
    let pin_path_server_to_group = "/sys/fs/bpf/smartblock_server_to_group";
    let pin_path_group_blocks = "/sys/fs/bpf/smartblock_group_blocks";
    let pin_path_group_names = "/sys/fs/bpf/smartblock_group_names";

    // Handle CLI commands
    if let Some(cmd) = opt.command {
        match cmd {
            Command::Add { target, action } => {
                let (ip, prefix) = parse_cidr(&target)?;
                let action_code: u32 = action.into();
                
                let stats_data = aya::maps::MapData::from_pin(pin_path_stats)?;
                let mut stats_map: HashMap<_, u32, BlockStats> = HashMap::try_from(aya::maps::Map::from_map_data(stats_data)?)?;
                
                let ip_u32 = u32::from(ip);
                let mask = if prefix == 0 { 0 } else { !((1u32 << (32 - prefix)) - 1) };
                let masked_ip_be = (ip_u32 & mask).to_be();
                
                let cidr_data = aya::maps::MapData::from_pin(pin_path_cidr)?;
                let mut cidr_map: LpmTrie<_, u32, u32> = LpmTrie::try_from(aya::maps::Map::from_map_data(cidr_data)?)?;
                let key = aya::maps::lpm_trie::Key::new(prefix, masked_ip_be);
                cidr_map.insert(&key, masked_ip_be, 0)?;
                
                let mut current_stats = stats_map.get(&masked_ip_be, 0).unwrap_or(BlockStats {
                    pkts: 0,
                    bytes: 0,
                    last_seen: 0,
                    action: action_code,
                    _pad: 0,
                });
                current_stats.action = action_code;
                stats_map.insert(&masked_ip_be, current_stats, 0)?;
                
                println!("Added {}/{} to blacklist (Action: {:?}, Masked Base: {})", ip, prefix, action, Ipv4Addr::from(ip_u32 & mask));
            }
            Command::Remove { target } => {
                let (ip, prefix) = parse_cidr(&target)?;
                let ip_u32 = u32::from(ip);
                let mask = if prefix == 0 { 0 } else { !((1u32 << (32 - prefix)) - 1) };
                let masked_ip_be = (ip_u32 & mask).to_be();

                let cidr_data = aya::maps::MapData::from_pin(pin_path_cidr)?;
                let mut cidr_map: LpmTrie<_, u32, u32> = LpmTrie::try_from(aya::maps::Map::from_map_data(cidr_data)?)?;
                let key = aya::maps::lpm_trie::Key::new(prefix, masked_ip_be);
                cidr_map.remove(&key)?;
                println!("Removed {}/{} from blacklist", ip, prefix);
            }
            Command::List => {
                let stats_data = aya::maps::MapData::from_pin(pin_path_stats)?;
                let stats_map: HashMap<_, u32, BlockStats> = HashMap::try_from(aya::maps::Map::from_map_data(stats_data)?)?;
                
                let cidr_data = aya::maps::MapData::from_pin(pin_path_cidr)?;
                let cidr_map: LpmTrie<_, u32, u32> = LpmTrie::try_from(aya::maps::Map::from_map_data(cidr_data)?)?;

                println!("\n=== Blacklist (CIDR / IP) ===");
                println!("{:<20} {:<10} {:<10} {:<12} {:<20}", "Target", "Action", "Packets", "Data Size", "Last Seen");
                println!("{:-<75}", "");
                
                for result in cidr_map.iter() {
                    let (key, base_ip_be) = result?;
                    let ip = Ipv4Addr::from(u32::from_be(key.data()));
                    if let Ok(stats) = stats_map.get(&base_ip_be, 0) {
                        let action_str = match stats.action {
                            ACTION_TARPIT => "TARPIT",
                            _ => "DROP",
                        };
                        println!("{:<20} {:<10} {:<10} {:<12} {:<20}", format!("{}/{}", ip, key.prefix_len()), action_str, stats.pkts, format_size(stats.bytes), "N/A");
                    } else {
                        println!("{:<20} {:<10} {:<10} {:<12} {:<20}", format!("{}/{}", ip, key.prefix_len()), "DROP", "0", "0 B", "N/A");
                    }
                }
            }
            Command::Group { command } => {
                match command {
                    GroupCommand::Add { group_name, server_ip, client_ip, action } => {
                        let group_id = get_group_id(&group_name);
                        let action_code: u32 = action.into();
                        
                        // Update SERVER_TO_GROUP
                        let s2g_data = aya::maps::MapData::from_pin(pin_path_server_to_group)?;
                        let mut s2g: HashMap<_, u32, u32> = HashMap::try_from(aya::maps::Map::from_map_data(s2g_data)?)?;
                        s2g.insert(u32::from(server_ip).to_be(), group_id, 0)?;

                        // Update GROUP_BLOCKS
                        let gb_data = aya::maps::MapData::from_pin(pin_path_group_blocks)?;
                        let mut gb: HashMap<_, GroupKey, u32> = HashMap::try_from(aya::maps::Map::from_map_data(gb_data)?)?;
                        let key = GroupKey { group_id, client_ip: u32::from(client_ip).to_be() };
                        gb.insert(key, action_code, 0)?;

                        // Ensure IP is in STATS pool
                        let stats_data = aya::maps::MapData::from_pin(pin_path_stats)?;
                        let mut stats_map: HashMap<_, u32, BlockStats> = HashMap::try_from(aya::maps::Map::from_map_data(stats_data)?)?;
                        let client_key = u32::from(client_ip).to_be();
                        let mut current_stats = stats_map.get(&client_key, 0).unwrap_or(BlockStats {
                            pkts: 0,
                            bytes: 0,
                            last_seen: 0,
                            action: action_code,
                            _pad: 0,
                        });
                        current_stats.action = action_code;
                        stats_map.insert(client_key, current_stats, 0)?;

                        // Update GROUP_NAMES
                        let gn_data = aya::maps::MapData::from_pin(pin_path_group_names)?;
                        let mut gn_map: HashMap<_, u32, [u8; 32]> = HashMap::try_from(aya::maps::Map::from_map_data(gn_data)?)?;
                        let mut name_bytes = [0u8; 32];
                        let bytes = group_name.as_bytes();
                        let len = bytes.len().min(32);
                        name_bytes[..len].copy_from_slice(&bytes[..len]);
                        gn_map.insert(group_id, name_bytes, 0)?;

                        println!("Added {} to group '{}' (ID: {}, Action: {:?}) for server {}", client_ip, group_name, group_id, action, server_ip);
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
                        println!("{:<15} {:<15} {:<25} {:<10} {:<10} {:<12}", "IP Address", "Group Name", "Server IPs", "Action", "Packets", "Data Size");
                        println!("{:-<95}", "");
                        
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
                            let action_code = stats.map(|s| s.action).unwrap_or(ACTION_DROP);
                            let action_str = match action_code {
                                ACTION_TARPIT => "TARPIT",
                                _ => "DROP",
                            };
                            let pkts = stats.map(|s| s.pkts).unwrap_or(0);
                            let bytes = stats.map(|s| s.bytes).unwrap_or(0);

                            println!("{:<15} {:<15} {:<25} {:<10} {:<10} {:<12}", client_ip_arc, group_name, servers, action_str, pkts, format_size(bytes));
                        }
                    }
                }
            }
        }
        return Ok(());
    }

    fn parse_cidr(target: &str) -> anyhow::Result<(Ipv4Addr, u32)> {
        if let Ok(ip) = Ipv4Addr::from_str(target) {
            Ok((ip, 32))
        } else if let Some((ip_str, prefix_str)) = target.split_once('/') {
            let ip = Ipv4Addr::from_str(ip_str)?;
            let prefix = prefix_str.parse::<u32>()?;
            if prefix > 32 {
                anyhow::bail!("Invalid prefix length: {}", prefix);
            }
            Ok((ip, prefix))
        } else {
            anyhow::bail!("Invalid IP or CIDR range: {}", target)
        }
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
        ("CIDR_BLOCKS", pin_path_cidr),
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
        _ = sigint.recv() => println!("* Stopping (SIGINT)..."),
        _ = sigterm.recv() => println!("* Stopping (SIGTERM)..."),
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
