# leaseguard

Stop VMs and containers on a Linux bridge from spoofing IP addresses or
running rogue DHCP servers.

leaseguard watches DHCP on the bridge and lets each port use only the IPv4
address its DHCP server handed out. Spoofed IPv4 and ARP, and DHCP or IPv6
router traffic from VMs, are dropped. It runs as eBPF programs in the kernel;
no packets go to userspace.

On a hardware switch this is called DHCP snooping, IP Source Guard and Dynamic
ARP Inspection.

> **Status: early.** Tested with dnsmasq, Kea, ISC dhcpd and libvirt, and with
> udhcpc, dhclient and dhcpcd. Start in monitor mode.

## Quick start

```sh
sudo apt install clang llvm libbpf-dev gcc make   # Ubuntu 24.04
make
sudo make install                                 # /usr/local/sbin/leaseguard
```

Run in monitor mode first. It logs what it would drop but drops nothing:

```sh
sudo leaseguard run --bridge vmbr0 --trusted eno1 \
    --leases dnsmasq:/var/lib/misc/dnsmasq.leases
```

- `--trusted` marks ports that are not checked: the uplink and the DHCP
  server's port. A DHCP server on the bridge host itself needs none.
- `--leases` binds clients that got their lease before leaseguard started.

Check `leaseguard bindings` and `leaseguard stats`. When the drops look like
attacks rather than your own hosts, turn on enforcement without a restart:

```sh
sudo leaseguard mode enforce --bridge vmbr0
```

Note that monitor mode does not block rogue DHCP servers either.

## What gets blocked

On each untrusted port:

| Check | Drops |
|---|---|
| IP source guard | IPv4 from a MAC/IP pair the port has no lease for |
| ARP inspection | ARP whose sender MAC/IP is not leased, or whose sender MAC is not the frame's source |
| Rogue DHCP guard | DHCP server and relay traffic; client messages with a forged chaddr or a giaddr |
| IPv6 router guard | Router advertisements, redirects, router renumbering, DHCPv6 server traffic |

ARP probes (sender 0.0.0.0) and DHCP client requests always pass, so clients
can get an address. IPv6 extension headers are walked so they cannot hide an RA
(RFC 7113). Use `--ipv6 drop` to block all IPv6 or `--ipv6 allow` to ignore it.

## How it works

```
                 trusted                       untrusted
  DHCP server ── eno1 ──┐                ┌── tap100i0 ── VM
                        │      br0       │
                        └────────────────┘   lg_ingress: VM -> bridge
                                             lg_egress:  bridge -> VM
```

Each untrusted port gets two TC programs:

- **`lg_ingress`** (VM → bridge) enforces the checks above and remembers each
  DHCP request: (port, VLAN, MAC) → transaction ID.
- **`lg_egress`** (bridge → VM) turns a DHCPACK that matches a remembered
  request into a binding: (port, VLAN, MAC) → IP, until the lease ends.
  RELEASE, DECLINE and NAK remove it.

Snooping replies on their way *out* to the port tells leaseguard both which
port a lease belongs to and that the server is trusted: server traffic from
untrusted ports never enters the bridge. Matching the request keeps a flooded
broadcast ACK from binding other ports.

Bindings live in pinned maps under `/sys/fs/bpf/leaseguard/<bridge>/` and
survive restarts. The daemon follows ports joining and leaving the bridge,
expires leases, and logs events. Programs attach with TCX (Linux 6.6+), or
clsact + cls_bpf on older kernels.

**Protection is off while the daemon is stopped.**

## Requirements

- Linux 6.6+ (TCX), or 5.8+ with `--attach tc`.
- libbpf 1.3+ and clang: Ubuntu 24.04, Debian 13, Fedora 39 or newer.
- Root, or CAP_BPF, CAP_NET_ADMIN and CAP_SYS_ADMIN.

## Reference

### Commands

```
leaseguard run       --bridge BR [--trusted PORT]... [--mode monitor|enforce]
                     [--ipv6 guard|drop|allow] [--static FILE] [--leases FMT:PATH]...
                     [--attach auto|tcx|tc] [--strict-ethertypes]
                     [--event-rate N] [--interval SECS] [-v]
leaseguard bindings  --bridge BR
leaseguard stats     --bridge BR
leaseguard mode      monitor|enforce --bridge BR
leaseguard reset     --bridge BR        # remove pinned state
leaseguard version
```

`--trusted` and `--leases` can be repeated; `--trusted` accepts globs
(`'en*'`). `--pin-dir DIR` can replace `--bridge`.

### Existing leases

Without `--leases`, a client that already had a lease when leaseguard started
is blocked until it renews. With it, the client's first dropped frame is
checked against the lease file. If there is a valid lease for exactly that MAC
and IP, and the IP is not bound elsewhere, it becomes a binding. In enforce
mode that one frame is lost and the client retries.

| Format | Server | Usual path |
|---|---|---|
| `dnsmasq` | dnsmasq, Incus/LXD, Proxmox SDN | `/var/lib/misc/dnsmasq.leases` |
| `libvirt` | libvirt networks | `/var/lib/libvirt/dnsmasq/<bridge>.status` |
| `kea` | Kea memfile | `/var/lib/kea/kea-leases4.csv` |
| `isc` | ISC dhcpd | `/var/lib/dhcp/dhcpd.leases` |

Files are re-read when they change. Imports never replace a snooped binding.
leaseguard trusts the lease file, so only the DHCP server should be able to
write it.

### Static bindings

For hosts with fixed addresses, pass `--static FILE` and send SIGHUP after
edits:

```
# port      mac                ip          [vlan]
tap100i0    bc:24:11:aa:bb:cc  10.0.0.5
tap101i0    bc:24:11:00:11:22  10.0.0.6    20
```

Bindings follow port names, so they reapply when a tap is recreated.

### Output

```
$ sudo leaseguard bindings --bridge br0
PORT             VLAN  MAC               IP              SOURCE  EXPIRES
c1p              0     02:00:00:00:00:c1 10.99.0.133     dhcp    in 1m57s
c3p              0     02:00:00:00:00:c3 10.99.0.210     static  never
```

SOURCE is `dhcp`, `import` (from a lease file) or `static`.

Logs are logfmt on stderr:

```
level=info msg=bind port=c1p vlan=0 mac=02:00:00:00:00:c1 ip=10.99.0.133 lease=120s
level=warn msg=drop reason=dhcp_server port=c2p vlan=0 mac=02:00:00:00:00:c2 ip=10.66.0.1
```

`leaseguard stats` counts each drop reason:

| Reason | Meaning |
|---|---|
| `no_binding` | source MAC has no binding on this port |
| `ip_mismatch` | MAC is bound to another IP |
| `expired` | lease has run out |
| `arp_sha_mismatch` | ARP sender MAC differs from the frame's source |
| `arp_unbound` | ARP sender MAC/IP pair is not bound |
| `dhcp_server` | DHCP server or relay traffic |
| `dhcp_chaddr` | DHCP chaddr differs from the frame's source |
| `dhcp_relayed` | DHCP request with giaddr set |
| `ipv6_router` | IPv6 RA, redirect or router renumbering |
| `dhcp6_server` | DHCPv6 server or relay traffic |
| `ipv6_policy` | IPv6 dropped by `--ipv6 drop` |
| `ipv6_exthdr` | IPv6 header chain too long or split across fragments |
| `vlan_inband` | stacked VLAN tag |
| `ethertype` | non-IP ethertype with `--strict-ethertypes` |
| `malformed` | truncated or invalid headers |

### systemd

One instance per bridge:

```sh
sudo cp contrib/leaseguard@.service /etc/systemd/system/
echo 'LEASEGUARD_OPTS="--trusted eno1 --mode monitor"' | sudo tee /etc/default/leaseguard-vmbr0
sudo systemctl enable --now leaseguard@vmbr0
```

## Limitations

- **IPv4 only.** IPv6 gets RA and DHCPv6 server guard, not source guard. If
  the bridge carries no IPv6, use `--ipv6 drop`.
- **Fail-open.** Nothing is enforced while the daemon is stopped.
- **Live migration.** A migrated VM has no binding on the new host until it
  renews, unless that host can read the lease file.
- **One DHCP address per port, VLAN and MAC.** Add static bindings for more.
- **MACs are not locked to ports.** Unbound MACs cannot use IPv4 or ARP, but
  other ethertypes pass unless `--strict-ethertypes` is set.
- **DHCP gaps.** No BOOTP-only clients, no option 52 overload, no option 82
  insertion, no DHCP rate limiting.
- **Network namespaces.** Use `nsenter --net`, not `ip netns exec`, which
  remounts /sys and hides the pinned state.

## Tests

```sh
make unit                   # lease file parsers
sudo make test              # datapath through the verifier (BPF_PROG_TEST_RUN)
sudo make e2e               # bridge, dnsmasq, udhcpc and an attacker in netns
sudo ATTACH=tc make e2e     # same, with tc attachment
sudo make interop           # real DHCP servers and clients, see below
```

The e2e test needs iproute2, util-linux, dnsmasq, busybox, ping and python3.

`make interop` runs leaseguard between each DHCP server and client it can
find: dnsmasq, Kea, ISC dhcpd and libvirt's lease helper, against busybox
udhcpc, ISC dhclient and dhcpcd. Each pair checks snooping, renewal, release
and importing the server's lease file. Narrow it down with `SERVERS=kea`,
`CLIENTS=dhcpcd`, and put the server behind ISC dhcrelay with `RELAY=1`.
Pairs whose tools are missing are skipped. On Ubuntu, unload the AppArmor
profiles of dhcpd, dhclient and kea-dhcp4 first (see `tests/interop.sh`).

## Prior art

Switch vendors' DHCP snooping,
[libvirt nwfilter](https://libvirt.org/formatnwfilter.html),
[ebtables-dhcpsnooping](https://github.com/michael-dev/ebtables-dhcpsnooping)
and [kdai](https://github.com/dentproject/kdai). leaseguard does the same in
eBPF on a Linux bridge.

## License

MIT. The eBPF program is also GPL-2.0-only (see its SPDX header) so the kernel
treats it as GPL-compatible.
