#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Send and sniff raw frames for the end-to-end test. Standard library only.

  netpkt.py send IFACE KIND SRC_MAC [ARGS...]
  netpkt.py sniff IFACE KIND SRC_MAC TIMEOUT READY_FILE

KIND is one of:
  garp IP     gratuitous ARP reply claiming IP
  ra          ICMPv6 router advertisement to ff02::1
  echo6       ICMPv6 echo request to ff02::1

sniff exits 0 if a matching frame from SRC_MAC arrived before TIMEOUT
seconds, 1 if not. It touches READY_FILE once its socket is listening.
"""
import select
import socket
import struct
import sys
import time

ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
BCAST = b"\xff" * 6
ALL_NODES_MAC = bytes.fromhex("333300000001")
ALL_NODES = socket.inet_pton(socket.AF_INET6, "ff02::1")


def mac(s):
    return bytes.fromhex(s.replace(":", ""))


def link_local(m):
    eui = bytearray(m[:3] + b"\xff\xfe" + m[3:])
    eui[0] ^= 0x02
    return b"\xfe\x80" + b"\x00" * 6 + bytes(eui)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def icmp6(src_mac, body):
    src = link_local(src_mac)
    pseudo = src + ALL_NODES + struct.pack("!I3xB", len(body), 58)
    body = body[:2] + struct.pack("!H", checksum(pseudo + body)) + body[4:]
    ip6 = struct.pack("!IHBB", 0x60000000, len(body), 58, 255) + src + ALL_NODES
    return ALL_NODES_MAC + src_mac + struct.pack("!H", ETH_P_IPV6) + ip6 + body


def frame(kind, src_mac, args):
    if kind == "garp":
        ip = socket.inet_aton(args[0])
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + src_mac + ip + BCAST + ip
        return BCAST + src_mac + struct.pack("!H", ETH_P_ARP) + arp
    if kind == "ra":
        # type, code, checksum, hop limit, flags, router lifetime, reachable, retrans
        return icmp6(src_mac, struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 1800, 0, 0))
    if kind == "echo6":
        return icmp6(src_mac, struct.pack("!BBHHH", 128, 0, 0, 0x4c47, 1) + b"leaseguard")
    raise SystemExit("unknown kind " + kind)


def matches(kind, f):
    if kind == "garp":
        return f[12:14] == struct.pack("!H", ETH_P_ARP)
    if f[12:14] != struct.pack("!H", ETH_P_IPV6) or f[20] != 58:
        return False
    return f[54] == {"ra": 134, "echo6": 128}[kind]


def main(argv):
    if len(argv) >= 4 and argv[1] == "send":
        iface, kind, src = argv[2], argv[3], mac(argv[4])
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as s:
            s.bind((iface, 0))
            s.send(frame(kind, src, argv[5:]))
        return 0
    if len(argv) == 7 and argv[1] == "sniff":
        iface, kind, src = argv[2], argv[3], mac(argv[4])
        deadline = time.monotonic() + float(argv[5])
        proto = ETH_P_ARP if kind == "garp" else ETH_P_IPV6
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto)) as s:
            # The protocol given to bind() replaces the socket's; 0 would
            # mean "receive nothing". Python converts it to network order.
            s.bind((iface, proto))
            open(argv[6], "w").close()
            while True:
                left = deadline - time.monotonic()
                if left <= 0 or not select.select([s], [], [], left)[0]:
                    return 1
                f = s.recv(4096)
                if f[6:12] == src and matches(kind, f):
                    return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
