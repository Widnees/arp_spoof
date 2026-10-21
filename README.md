# ARP Spoof

A Linux command-line ARP/NDP spoofing demonstration written in Rust for isolated, authorized network labs. It covers both IPv4 and IPv6 and replaces the earlier Python version of this repository.

The application discovers IPv4 devices using ARP and observes IPv6 hosts through their link-local traffic. It sends forged ARP replies between discovered devices and the default gateway, and forged IPv6 router and neighbor advertisements for the gateway. This can redirect traffic to the local machine and interrupt connectivity. On Ctrl+C, it attempts to restore the original ARP and NDP mappings.

> Run only in an isolated lab where you have explicit authorization for every affected device and the gateway. At startup the program asks for an attack mode and, for the targeted modes, which devices to affect or protect; there is no dry-run mode, so confirm scope before continuing.

## Features

- Automatic selection of an active IPv4 interface and detection of a default gateway.
- Gateway MAC address resolution through ARP and gateway link-local IPv6 discovery through a router solicitation.
- Initial discovery followed by periodic background scans. The scan range follows the interface's prefix length and is capped at `/22`.
- Interactive attack-mode selection: one or more selected targets, everyone, or everyone except one or more protected devices. The target picker keeps scanning in the background, refreshes automatically, and lets you move through the list with the arrow keys (or `j`/`k`), toggle devices with Space, and confirm with Enter.
- Hybrid IPv4 and IPv6 spoofing: ARP replies for IPv4, and forged router advertisements plus neighbor advertisements for IPv6. Targeted modes use unicast neighbor advertisements.
- Immediate replies to ARP requests for the gateway or local address, and to IPv6 neighbor solicitations for the gateway, keeping neighbor entries pointed at this machine.
- Separate threads for receiving ARP/NDP traffic, sending forged packets, scanning, and displaying status.
- Live status: IPv4 and IPv6 device counts, packet attempts, immediate replies, background scan cycles, elapsed time, attack mode, and forwarding state.
- Disables IPv4 and IPv6 forwarding while running and restores the previous values on exit.
- Best-effort ARP and NDP restoration when stopped with Ctrl+C.

## Requirements

- Linux: the implementation reads `/proc/net/route`, `/proc/self/status`, `/proc/sys/net/ipv4/ip_forward`, and `/proc/sys/net/ipv6/conf/all/forwarding`.
- A Rust toolchain with Cargo and a system linker compatible with the dependencies in `Cargo.lock`.
- An Ethernet-compatible IPv4 lab network with a reachable gateway. IPv6 coverage additionally requires a link-local IPv6 address on the interface and a reachable IPv6 router.
- Root privileges or the effective `CAP_NET_RAW` capability at runtime, plus permission to change the forwarding sysctls if they are enabled.
- An interactive terminal for the target picker; the on-screen interface is in Turkish.

Dependencies are `pnet` for network interfaces and packet construction, `ctrlc` for interrupt handling, and `libc` for the effective-user-ID check, terminal raw mode, and `ioctl`/`poll` calls.

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

There are no command-line options. Starting the executable selects the interface and default gateway, resolves the gateway's MAC address and, when available, its link-local IPv6 address, then prompts for an attack mode: one or more selected targets, everyone, or everyone except one or more protected devices. It then runs the initial discovery scan and, for the two targeted modes, opens a picker for the affected or protected devices. In the target picker, move the highlight with the arrow keys (or `j`/`k`), press Space to select or deselect the highlighted device, and press Enter to confirm the selection. `c` clears the selection and `q` cancels. The list keeps refreshing while it is open, and the highlight and selection follow devices by MAC address. Do not rely on `--help` or other arguments to prevent execution: arguments are not parsed.

Press **Ctrl+C** to request shutdown and attempt ARP/NDP restoration. Worker threads stop promptly and the main thread waits up to 3 seconds for them; the corrective send that follows can take longer depending on how many devices were recorded. Restoration is best effort; verify connectivity independently afterward.

The application disables IPv4 and IPv6 forwarding while it runs if they were enabled, and restores only the settings it changed on exit: forwarding would make the redirected traffic a man-in-the-middle path instead of a cut. If the settings cannot be changed (for example, without sufficient privileges), the program warns that connectivity may not be interrupted.

## How it works

1. Check for root privileges or effective `CAP_NET_RAW`.
2. Select the first eligible active, non-loopback IPv4 interface, excluding several common virtual-interface name prefixes. The program warns if the interface name does not look like a Wi-Fi device (`wl*`), but continues.
3. Read a default gateway from the Linux routing table and resolve its MAC address with ARP. If the interface has an IPv6 link-local address, send a router solicitation to learn the gateway's link-local IPv6 address.
4. Prompt for an attack mode.
5. Probe the interface's actual IPv4 subnet, computed from its prefix length (capped at `/22` for very large networks), excluding the network, broadcast, local, and gateway addresses.
6. For the selected-targets and except-selected modes, open an interactive picker for the affected or protected devices; the picker keeps scanning in the background and refreshes the list automatically.
7. Record devices from ARP requests and replies within the interface subnet, and IPv6 hosts from link-local traffic. Entries are kept for the rest of the run.
8. Repeat a sending cycle every 500 ms:
   - **IPv4:** for every recorded device, send a forged reply claiming the gateway is at the local MAC. In the everyone and except-selected modes, also send the reverse forged reply to the gateway claiming the device is at the local MAC. The selected-targets mode omits the gateway-side reply, so only the selected devices' view of the gateway changes.
   - **IPv6, everyone mode:** send a forged router advertisement and neighbor advertisement for the gateway to the all-nodes group, plus neighbor advertisements for recorded IPv6 hosts.
   - **IPv6, targeted modes:** send unicast neighbor advertisements claiming the gateway's link-local address only to the affected devices. Missing link-local addresses are learned with a periodic `ff02::1` echo request.
9. Respond immediately to ARP requests for the gateway or local address with a forged reply, and to IPv6 neighbor solicitations for the gateway with a solicited neighbor advertisement.
10. Run background discovery every 30 seconds. The selected-targets mode disables background discovery.
11. On Ctrl+C, send corrective ARP replies for each recorded device in each direction that was poisoned, and corrective NDP advertisements for recorded IPv6 hosts.

Timing constants are defined near the top of `src/main.rs`. The initial discovery wait is 6 seconds, the background discovery wait is 2 seconds, and the spoofing interval is 500 ms.

## Limitations

- **Scope depends on the mode:** the everyone mode includes every recorded device. The selected-targets and except-selected modes rely on the interactive device selection and on the selected MAC addresses, so devices that share, spoof, or change MAC addresses can be mis-scoped.
- **IPv6 coverage depends on the mode:** the everyone mode advertises forged router and neighbor entries to the whole link, so IPv6 is affected for every host. The targeted modes send unicast neighbor advertisements only to the affected devices. That path needs each device's link-local IPv6 address; the program asks for it with a multicast echo request, so a device that never answers and whose address is never observed may keep IPv6 connectivity.
- **Scan range cap:** discovery follows the interface's actual prefix length, but networks larger than a `/22` are scanned only within the `/22` that contains the local address.
- **Multiple interfaces:** interface selection and default-route selection are independent. VPNs, multiple adapters, and complex routes can produce an incorrect pairing.
- **Recording scope and lifetime:** devices can be recorded from any ARP request or reply inside the interface subnet, not only from the capped scan range, and recorded entries never expire. A device that changes address or leaves the network can remain in the target list.
- **Selected-targets direction:** in selected-targets mode the gateway is never poisoned. Only the selected devices are told that the gateway is at the local MAC, so the gateway keeps the devices' real MAC addresses in its own ARP cache.
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
├── .gitignore       # Excludes Cargo build output and local .serena tooling
├── Cargo.lock       # Pinned dependency resolution
├── Cargo.toml       # Package, dependencies, and release profile
├── README.md        # Documentation and disclaimer
└── src/
    └── main.rs      # Application implementation
```

## Disclaimer and responsible use

This project is provided for education, research, and explicitly authorized security testing. Publication of the source code is not permission to access, manipulate, intercept, or disrupt any network or device.

**Authorization and scope.** Use the software only on systems you own or for which you have explicit prior permission from the responsible owner or administrator. Permission for one device does not imply permission for the gateway, other connected devices, other users' traffic, or shared infrastructure. Agree on the testing scope, timing, affected systems, and recovery procedures before execution. Because device discovery is automatic even when targets are selected interactively, an isolated test network is essential to keeping activity within scope.

**Operational risks.** ARP/NDP spoofing can cause traffic redirection, outages, unstable connections, interrupted sessions, loss of in-flight data, and exposure of private communications. Effects may extend beyond the intended test device. Do not use this software on public, workplace, school, production, emergency, healthcare, or other sensitive networks without explicit authorization covering the activity and all potentially affected systems.

**Privacy and compliance.** You are responsible for protecting other people's information and for complying with applicable laws, contracts, network policies, and authorization requirements. Do not use this project for unauthorized interception, surveillance, credential theft, service disruption, or evasion of access restrictions. An educational purpose does not itself establish authorization or make prohibited conduct permissible.

**No warranty.** The software and documentation are provided “as is” and “as available,” without warranties of any kind, express or implied, including accuracy, fitness for a particular purpose, merchantability, non-infringement, reliability, or uninterrupted operation. Network detection, packet transmission, displayed status, and cleanup may be incomplete or incorrect. No claim is made that stopping the application will restore connectivity or reverse every effect.

**Responsibility and liability.** You are responsible for evaluating the code, obtaining authorization, isolating the environment, monitoring effects, protecting data, and restoring affected systems. To the extent permitted by applicable law, the authors and contributors disclaim liability for losses or damages arising from use, misuse, inability to use, or reliance on this software or its documentation, including network downtime, data loss, privacy breaches, and third-party claims. This disclaimer does not override rights or liabilities that applicable law does not allow to be excluded.

**Recovery and advice.** Maintain an independent recovery path and verify the state of affected hosts and the gateway after testing. This document is a statement of intended use and risk, not legal advice or a guarantee of safety. If authorization or scope is uncertain, obtain clarification from the responsible owner before running the program.
