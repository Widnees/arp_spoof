# ARP Spoof

A Linux command-line ARP spoofing demonstration written in Rust for isolated, authorized network labs. This implementation replaces the earlier Python version of this repository.

The application discovers IPv4 devices using ARP and sends forged ARP replies between discovered devices and the default gateway. This can redirect traffic to the local machine and interrupt connectivity. On Ctrl+C, it attempts to restore the original ARP mappings.

> Run only in an isolated lab where you have explicit authorization for every affected device and the gateway. The program starts automatically and has no target selector or dry-run mode.

## Features

- Automatic selection of an active IPv4 interface and detection of a default gateway.
- Gateway MAC address resolution through ARP.
- Initial discovery followed by periodic background scans.
- Separate threads for receiving ARP replies, sending forged replies, scanning, and displaying status.
- Live device count, packet attempt count, background scan count, elapsed time, and IPv4 forwarding status.
- Best-effort ARP restoration when stopped with Ctrl+C.

## Requirements

- Linux: the implementation reads `/proc/net/route`, `/proc/self/status`, and `/proc/sys/net/ipv4/ip_forward`.
- A Rust toolchain with Cargo and a system linker compatible with the dependencies in `Cargo.lock`.
- An Ethernet-compatible IPv4 lab network with a reachable gateway.
- Root privileges or the effective `CAP_NET_RAW` capability at runtime.

Dependencies are `pnet` for network interfaces and packet construction, `ctrlc` for interrupt handling, and `libc` for the effective-user-ID check.

## Build

```sh
git clone https://github.com/Widnees/arp_spoof.git
cd arp_spoof
cargo build --release --locked
```

The executable is created at `target/release/arp_spoof`. Build artifacts are excluded from version control; `Cargo.lock` is committed for reproducible dependency resolution.

## Run in an authorized lab

Before starting, isolate the test network, confirm that all attached devices are in scope, and ensure that you have a way to recover the lab's connectivity.

```sh
sudo ./target/release/arp_spoof
```

There are no command-line options. Starting the executable immediately begins network detection and discovery, followed by spoofing of discovered devices. Do not rely on `--help` or other arguments to prevent execution: arguments are not parsed.

Press **Ctrl+C** to request shutdown and attempt ARP restoration. The background scanner sleeps between scans, so the process may take approximately 15 seconds to finish exiting. Restoration is best effort; verify connectivity independently afterward.

The application reports the system's IPv4 forwarding setting but does not modify it. Disabled forwarding can cause loss of connectivity when traffic is redirected to this machine. Enabled forwarding alone does not guarantee connectivity: routing, firewall rules, and network protections also matter.

## How it works

1. Check for root privileges or effective `CAP_NET_RAW`.
2. Select the first eligible active, non-loopback IPv4 interface, excluding several common virtual-interface name prefixes.
3. Read a default gateway from the Linux routing table and resolve its MAC address.
4. Probe host addresses `.1` through `.254` in the gateway's assumed `/24`, excluding the local and gateway addresses.
5. Record devices from received ARP replies and send forged replies in both directions between each device and the gateway, advertising the local MAC address.
6. Repeat the sending cycle every 2 seconds and run background discovery after each 15-second scanner sleep.
7. On Ctrl+C, attempt to send five corrective replies in each direction for each recorded device.

Timing constants are defined near the top of `src/main.rs`. The initial discovery wait is 2 seconds and the background discovery wait is 800 milliseconds.

## Limitations

- **Broad scope:** every recorded device is included. There is no allowlist, single-target mode, or interactive confirmation.
- **Fixed scan range:** discovery assumes the gateway's `/24`; it does not calculate the range from the interface's actual subnet mask.
- **Multiple interfaces:** interface selection and default-route selection are independent. VPNs, multiple adapters, and complex routes can produce an incorrect pairing.
- **Reply collection:** received ARP replies are not restricted to the probed range, and recorded devices are not expired from the target map.
- **IPv4 only:** this does not implement IPv6 neighbor discovery manipulation.
- **Environment dependent:** client isolation, ARP protections, static neighbor entries, and link-layer restrictions can prevent operation.
- **Attempt counters:** packet counts measure send attempts, not confirmed delivery. Most send errors are ignored.
- **Recovery is not guaranteed:** corrective replies may be rejected or lost. Crashes, forced termination, power loss, and some termination signals can bypass cleanup. The shutdown path does not confirm that remote ARP caches have recovered.
- **No traffic analysis:** the application does not implement packet capture storage, credential extraction, or application-layer traffic inspection.

## Development checks

```sh
cargo fmt --check
cargo check --locked
cargo clippy --locked
cargo build --release --locked
```

These commands check formatting and compilation without running the application or transmitting ARP traffic. They do not validate behavior on a live network. Any runtime testing must be performed separately in an isolated, authorized lab.

## Project layout

```text
.
├── .gitignore       # Excludes Cargo build output
├── Cargo.lock       # Pinned dependency resolution
├── Cargo.toml       # Package, dependencies, and release profile
├── README.md        # Documentation and disclaimer
└── src/
    └── main.rs      # Application implementation
```

## Disclaimer and responsible use

This project is provided for education, research, and explicitly authorized security testing. Publication of the source code is not permission to access, manipulate, intercept, or disrupt any network or device.

**Authorization and scope.** Use the software only on systems you own or for which you have explicit prior permission from the responsible owner or administrator. Permission for one device does not imply permission for the gateway, other connected devices, other users' traffic, or shared infrastructure. Agree on the testing scope, timing, affected systems, and recovery procedures before execution. Because this version automatically discovers and includes devices, an isolated test network is essential to keeping activity within scope.

**Operational risks.** ARP spoofing can cause traffic redirection, outages, unstable connections, interrupted sessions, loss of in-flight data, and exposure of private communications. Effects may extend beyond the intended test device. Do not use this software on public, workplace, school, production, emergency, healthcare, or other sensitive networks without explicit authorization covering the activity and all potentially affected systems.

**Privacy and compliance.** You are responsible for protecting other people's information and for complying with applicable laws, contracts, network policies, and authorization requirements. Do not use this project for unauthorized interception, surveillance, credential theft, service disruption, or evasion of access restrictions. An educational purpose does not itself establish authorization or make prohibited conduct permissible.

**No warranty.** The software and documentation are provided “as is” and “as available,” without warranties of any kind, express or implied, including accuracy, fitness for a particular purpose, merchantability, non-infringement, reliability, or uninterrupted operation. Network detection, packet transmission, displayed status, and cleanup may be incomplete or incorrect. No claim is made that stopping the application will restore connectivity or reverse every effect.

**Responsibility and liability.** You are responsible for evaluating the code, obtaining authorization, isolating the environment, monitoring effects, protecting data, and restoring affected systems. To the extent permitted by applicable law, the authors and contributors disclaim liability for losses or damages arising from use, misuse, inability to use, or reliance on this software or its documentation, including network downtime, data loss, privacy breaches, and third-party claims. This disclaimer does not override rights or liabilities that applicable law does not allow to be excluded.

**Recovery and advice.** Maintain an independent recovery path and verify the state of affected hosts and the gateway after testing. This document is a statement of intended use and risk, not legal advice or a guarantee of safety. If authorization or scope is uncertain, obtain clarification from the responsible owner before running the program.
