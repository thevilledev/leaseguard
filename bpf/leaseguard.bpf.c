// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * leaseguard datapath: DHCP snooping, IPv4 source guard, ARP inspection and
 * rogue DHCP/RA guard for the untrusted ports of a Linux bridge.
 *
 * Two programs run on every untrusted port:
 *
 *   lg_ingress  frames entering the bridge from the port (guest -> LAN)
 *   lg_egress   frames leaving the bridge toward the port (LAN -> guest)
 *
 * lg_egress watches DHCPv4 replies on their way to the client and turns an
 * ACK into a binding (port, vlan, mac) -> ip that lasts as long as the lease.
 * A reply only binds when this same port sent the matching request (same
 * chaddr and xid, recorded by lg_ingress), so a broadcast ACK flooded to every
 * port binds only the port that asked for it. Any reply that reaches an
 * untrusted port's egress came from a trusted source, because lg_ingress drops
 * DHCP server traffic from untrusted ports; this also covers a DHCP server
 * running on the bridge host itself.
 *
 * lg_ingress checks IPv4 source addresses and ARP senders against those
 * bindings, drops DHCP server traffic, IPv6 router messages and DHCPv6 server
 * traffic coming from the port, and records outstanding DHCP requests.
 *
 * Trusted ports (uplinks, the DHCP server's port) carry no program at all.
 *
 * Allowed frames return TC_ACT_UNSPEC so that programs attached after this
 * one still run; violations return TC_ACT_SHOT in enforce mode.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "leaseguard.h"

#define NSEC_PER_SEC        1000000000ULL

#define IPPROTO_UDP_        17
#define IPPROTO_ICMPV6_     58

#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68
#define DHCP6_CLIENT_PORT   546
#define DHCP6_SERVER_PORT   547

#define BOOTREQUEST         1
#define BOOTREPLY           2
#define BOOTP_HTYPE_ETHER   1
#define BOOTP_MAGIC_OFF     236
#define BOOTP_OPTIONS_OFF   240
#define DHCP_MAGIC          0x63825363

#define DHCP_OPT_PAD        0
#define DHCP_OPT_LEASE_TIME 51
#define DHCP_OPT_MSG_TYPE   53
#define DHCP_OPT_END        255
#define DHCP_MAX_OPTIONS    64

#define DHCPDISCOVER        1
#define DHCPREQUEST         3
#define DHCPDECLINE         4
#define DHCPACK             5
#define DHCPNAK             6
#define DHCPRELEASE         7

#define ARP_HTYPE_ETHER     1

#define IPV6_HDR_LEN        40
#define IPV6_NEXTHDR_OFF    6
#define NEXTHDR_HOP         0
#define NEXTHDR_ROUTING     43
#define NEXTHDR_FRAGMENT    44
#define NEXTHDR_AUTH        51
#define NEXTHDR_DEST        60
#define IPV6_MAX_EXT_HDRS   8
#define IPV6_FRAG_OFF_MASK  0xfff8

#define ICMPV6_ROUTER_ADV   134
#define ICMPV6_REDIRECT     137
#define ICMPV6_ROUTER_RENUM 138

#define VLAN_VID_MASK       0x0fff
#define IP_FRAG_OFFSET      0x1fff

/* Fixed part of a BOOTP message, up to and including chaddr. */
struct bootp {
	__u8  op;
	__u8  htype;
	__u8  hlen;
	__u8  hops;
	__u32 xid;
	__u16 secs;
	__u16 flags;
	__u32 ciaddr;
	__u32 yiaddr;
	__u32 siaddr;
	__u32 giaddr;
	__u8  chaddr[16];
};

/* The DHCP options leaseguard cares about. */
struct dhcp_opts {
	__u32 lease_be;  /* option 51, network byte order, 0 if absent */
	__u8  msg_type;  /* option 53, 0 if absent */
	__u8  _pad[3];
};

/* ARP for IPv4 over Ethernet. */
struct arp_ipv4 {
	__be16 htype;
	__be16 ptype;
	__u8   hlen;
	__u8   plen;
	__be16 oper;
	__u8   sha[ETH_ALEN];
	__u8   spa[4];
	__u8   tha[ETH_ALEN];
	__u8   tpa[4];
};

struct lg_ratelimit {
	__u64 window_ns;
	__u64 count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lg_key);
	__type(value, struct lg_lease);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} lg_leases SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lg_static_key);
	__type(value, __u32);
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} lg_static SEC(".maps");

/* LRU so that a flood of DISCOVERs cannot exhaust it. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct lg_key);
	__type(value, struct lg_pending_req);
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} lg_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct lg_config);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} lg_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, LG_COUNTER_SLOTS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} lg_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct lg_ratelimit);
	__uint(max_entries, 1);
} lg_ratelimit SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} lg_events SEC(".maps");

static __always_inline __u64 now_ns(void)
{
	return bpf_ktime_get_boot_ns();
}

static __always_inline void count(__u32 reason)
{
	__u64 *c = bpf_map_lookup_elem(&lg_counters, &reason);

	if (c)
		*c += 1;
}

static __always_inline int mac_eq(const __u8 *a, const __u8 *b)
{
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
	       a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
}

static __always_inline void emit(const struct lg_key *k, __u32 ip,
				 __u32 lease_secs, __u16 reason, __u16 kind)
{
	struct lg_event ev = {
		.ts_ns = now_ns(),
		.ifindex = k->ifindex,
		.ip = ip,
		.lease_secs = lease_secs,
		.vlan = k->vlan,
		.reason = reason,
		.kind = kind,
	};

	__builtin_memcpy(ev.mac, k->mac, ETH_ALEN);
	bpf_ringbuf_output(&lg_events, &ev, sizeof(ev), 0);
}

/* Per-CPU budget for drop events, so a flood cannot swamp the daemon. */
static __always_inline int event_budget(const struct lg_config *cfg)
{
	__u32 zero = 0;
	struct lg_ratelimit *rl = bpf_map_lookup_elem(&lg_ratelimit, &zero);
	__u64 limit = cfg->event_rate ? cfg->event_rate : LG_DEFAULT_EVENT_RATE;
	__u64 now;

	if (!rl)
		return 0;
	now = now_ns();
	if (now - rl->window_ns >= NSEC_PER_SEC) {
		rl->window_ns = now;
		rl->count = 0;
	}
	if (rl->count >= limit)
		return 0;
	rl->count++;
	return 1;
}

static __always_inline int allow(__u32 reason)
{
	count(reason);
	return TC_ACT_UNSPEC;
}

static __always_inline int deny(const struct lg_config *cfg,
				const struct lg_key *k, __u32 ip, __u32 reason)
{
	int enforce = cfg->mode == LG_MODE_ENFORCE;

	count(reason);
	if (event_budget(cfg))
		emit(k, ip, 0, reason, enforce ? LG_EV_DROP : LG_EV_WOULD_DROP);
	return enforce ? TC_ACT_SHOT : TC_ACT_UNSPEC;
}

/*
 * Is (port, vlan, mac) allowed to use ip? A DHCP lease or a static binding
 * both count. On failure *reason says why the lease did not match.
 */
static __always_inline int bound(const struct lg_key *k, __u32 ip, __u32 *reason)
{
	struct lg_lease *l = bpf_map_lookup_elem(&lg_leases, k);
	struct lg_static_key sk = {};

	*reason = LG_R_NO_BINDING;
	if (l) {
		if (l->ip != ip)
			*reason = LG_R_IP_MISMATCH;
		else if (l->expires_ns && now_ns() > l->expires_ns)
			*reason = LG_R_EXPIRED;
		else
			return 1;
	}

	sk.ifindex = k->ifindex;
	sk.vlan = k->vlan;
	sk.ip = ip;
	__builtin_memcpy(sk.mac, k->mac, ETH_ALEN);
	return bpf_map_lookup_elem(&lg_static, &sk) != NULL;
}

static __always_inline void fill_key(struct __sk_buff *skb, struct lg_key *k,
				     const __u8 *mac)
{
	k->ifindex = skb->ifindex;
	k->vlan = skb->vlan_present ? (skb->vlan_tci & VLAN_VID_MASK) : 0;
	__builtin_memcpy(k->mac, mac, ETH_ALEN);
}

/*
 * Walk the options after the magic cookie. Returns 0 if the message has no
 * DHCP magic cookie (plain BOOTP), 1 otherwise. Option overloading into the
 * sname/file fields is not followed.
 */
static __always_inline int dhcp_options(struct __sk_buff *skb, __u32 bootp_off,
					struct dhcp_opts *o)
{
	__u32 off = bootp_off + BOOTP_OPTIONS_OFF;
	__u32 magic;

	if (bpf_skb_load_bytes(skb, bootp_off + BOOTP_MAGIC_OFF, &magic, sizeof(magic)) < 0 ||
	    magic != bpf_htonl(DHCP_MAGIC))
		return 0;

	for (int i = 0; i < DHCP_MAX_OPTIONS; i++) {
		__u8 code, len;

		if (bpf_skb_load_bytes(skb, off, &code, 1) < 0 || code == DHCP_OPT_END)
			break;
		if (code == DHCP_OPT_PAD) {
			off++;
			continue;
		}
		if (bpf_skb_load_bytes(skb, off + 1, &len, 1) < 0)
			break;
		if (code == DHCP_OPT_MSG_TYPE && len == 1)
			bpf_skb_load_bytes(skb, off + 2, &o->msg_type, 1);
		else if (code == DHCP_OPT_LEASE_TIME && len == 4)
			bpf_skb_load_bytes(skb, off + 2, &o->lease_be, 4);
		off += 2 + (__u32)len;
	}
	return 1;
}

/* A client message entering the bridge: validate it, then remember it. */
static __always_inline int ingress_dhcp(struct __sk_buff *skb,
					const struct lg_config *cfg,
					const struct lg_key *k, __u32 off)
{
	struct dhcp_opts o = {};
	struct lg_lease *l;
	struct bootp b;

	if (bpf_skb_load_bytes(skb, off, &b, sizeof(b)) < 0)
		return deny(cfg, k, 0, LG_R_MALFORMED);
	if (b.op != BOOTREQUEST)
		return deny(cfg, k, 0, LG_R_DHCP_SERVER);
	if (b.htype != BOOTP_HTYPE_ETHER || b.hlen != ETH_ALEN || !mac_eq(b.chaddr, k->mac))
		return deny(cfg, k, 0, LG_R_DHCP_CHADDR);
	if (b.giaddr)
		return deny(cfg, k, 0, LG_R_DHCP_RELAYED);

	if (!dhcp_options(skb, off, &o))
		return allow(LG_R_PASS_DHCP);

	switch (o.msg_type) {
	case DHCPDISCOVER:
	case DHCPREQUEST: {
		/* DISCOVER too: with rapid commit (RFC 4039) the ACK answers it. */
		struct lg_pending_req p = { .xid = b.xid, .ts_ns = now_ns() };

		bpf_map_update_elem(&lg_pending, k, &p, BPF_ANY);
		count(LG_R_DHCP_REQUEST);
		break;
	}
	case DHCPRELEASE:
	case DHCPDECLINE:
		/*
		 * The frame's source MAC equals chaddr and the key includes the
		 * port, so a client can only give up its own binding.
		 */
		l = bpf_map_lookup_elem(&lg_leases, k);
		if (l && (o.msg_type == DHCPDECLINE || l->ip == b.ciaddr)) {
			__u32 ip = l->ip;
			__u32 r = o.msg_type == DHCPRELEASE ? LG_R_RELEASE : LG_R_DECLINE;

			bpf_map_delete_elem(&lg_leases, k);
			count(r);
			emit(k, ip, 0, r, LG_EV_UNBIND);
		}
		break;
	}
	return allow(LG_R_PASS_DHCP);
}

static __always_inline int ingress_ipv4(struct __sk_buff *skb,
					const struct lg_config *cfg,
					const struct lg_key *k)
{
	struct iphdr ip;
	__u32 reason;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)) < 0 ||
	    ip.version != 4 || ip.ihl < 5)
		return deny(cfg, k, 0, LG_R_MALFORMED);

	/* Only the first fragment carries the UDP header. */
	if (ip.protocol == IPPROTO_UDP_ && !(ip.frag_off & bpf_htons(IP_FRAG_OFFSET))) {
		__u32 l4 = ETH_HLEN + ip.ihl * 4;
		struct udphdr udp;
		__u16 sport, dport;

		if (bpf_skb_load_bytes(skb, l4, &udp, sizeof(udp)) < 0)
			return deny(cfg, k, ip.saddr, LG_R_MALFORMED);
		sport = bpf_ntohs(udp.source);
		dport = bpf_ntohs(udp.dest);
		/* Servers and relays answer from port 67 or to port 68. */
		if (sport == DHCP_SERVER_PORT || dport == DHCP_CLIENT_PORT)
			return deny(cfg, k, ip.saddr, LG_R_DHCP_SERVER);
		/*
		 * Client messages pass whatever their source address: in INIT
		 * and REBOOT it is 0.0.0.0, the client has no lease yet.
		 */
		if (sport == DHCP_CLIENT_PORT && dport == DHCP_SERVER_PORT)
			return ingress_dhcp(skb, cfg, k, l4 + sizeof(udp));
	}

	if (bound(k, ip.saddr, &reason))
		return allow(LG_R_PASS_IPV4);
	return deny(cfg, k, ip.saddr, reason);
}

static __always_inline int ingress_arp(struct __sk_buff *skb,
				       const struct lg_config *cfg,
				       const struct lg_key *k)
{
	struct arp_ipv4 a;
	__u32 spa, reason;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &a, sizeof(a)) < 0 ||
	    a.htype != bpf_htons(ARP_HTYPE_ETHER) || a.ptype != bpf_htons(ETH_P_IP) ||
	    a.hlen != ETH_ALEN || a.plen != 4)
		return deny(cfg, k, 0, LG_R_MALFORMED);

	__builtin_memcpy(&spa, a.spa, sizeof(spa));
	if (!mac_eq(a.sha, k->mac))
		return deny(cfg, k, spa, LG_R_ARP_SHA_MISMATCH);
	/* Address conflict probes (RFC 5227) have no sender address yet. */
	if (spa == 0)
		return allow(LG_R_PASS_ARP);
	if (bound(k, spa, &reason))
		return allow(LG_R_PASS_ARP);
	return deny(cfg, k, spa, LG_R_ARP_UNBOUND);
}

/*
 * RA guard (RFC 6105) and DHCPv6 server guard. The extension header chain is
 * walked so that headers cannot hide an RA (RFC 7113); a first fragment that
 * does not hold the whole chain is dropped (RFC 7112).
 */
static __always_inline int ingress_ipv6(struct __sk_buff *skb,
					const struct lg_config *cfg,
					const struct lg_key *k)
{
	__u32 off = ETH_HLEN + IPV6_HDR_LEN;
	__u8 nh;

	if (cfg->ipv6_policy == LG_IPV6_ALLOW)
		return allow(LG_R_PASS_IPV6);
	if (cfg->ipv6_policy == LG_IPV6_DROP)
		return deny(cfg, k, 0, LG_R_IPV6_POLICY);

	if (bpf_skb_load_bytes(skb, ETH_HLEN + IPV6_NEXTHDR_OFF, &nh, 1) < 0)
		return deny(cfg, k, 0, LG_R_MALFORMED);

	for (int i = 0; i < IPV6_MAX_EXT_HDRS; i++) {
		__u8 h[4];

		switch (nh) {
		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_DEST:
			if (bpf_skb_load_bytes(skb, off, h, 2) < 0)
				return deny(cfg, k, 0, LG_R_IPV6_EXTHDR);
			nh = h[0];
			off += ((__u32)h[1] + 1) * 8;
			continue;
		case NEXTHDR_AUTH:
			if (bpf_skb_load_bytes(skb, off, h, 2) < 0)
				return deny(cfg, k, 0, LG_R_IPV6_EXTHDR);
			nh = h[0];
			off += ((__u32)h[1] + 2) * 4;
			continue;
		case NEXTHDR_FRAGMENT:
			if (bpf_skb_load_bytes(skb, off, h, 4) < 0)
				return deny(cfg, k, 0, LG_R_IPV6_EXTHDR);
			/* Later fragments carry no upper-layer header. */
			if ((((__u32)h[2] << 8) | h[3]) & IPV6_FRAG_OFF_MASK)
				return allow(LG_R_PASS_IPV6);
			nh = h[0];
			off += 8;
			continue;
		}
		goto upper;
	}
	return deny(cfg, k, 0, LG_R_IPV6_EXTHDR);

upper:
	if (nh == IPPROTO_ICMPV6_) {
		__u8 type;

		if (bpf_skb_load_bytes(skb, off, &type, 1) < 0)
			return deny(cfg, k, 0, LG_R_IPV6_EXTHDR);
		if (type == ICMPV6_ROUTER_ADV || type == ICMPV6_REDIRECT ||
		    type == ICMPV6_ROUTER_RENUM)
			return deny(cfg, k, 0, LG_R_IPV6_ROUTER);
	} else if (nh == IPPROTO_UDP_) {
		__be16 ports[2];

		if (bpf_skb_load_bytes(skb, off, ports, sizeof(ports)) < 0)
			return deny(cfg, k, 0, LG_R_IPV6_EXTHDR);
		/* Servers and relays send from 547; only servers send to 546. */
		if (ports[0] == bpf_htons(DHCP6_SERVER_PORT) ||
		    ports[1] == bpf_htons(DHCP6_CLIENT_PORT))
			return deny(cfg, k, 0, LG_R_DHCP6_SERVER);
	}
	return allow(LG_R_PASS_IPV6);
}

SEC("tcx/ingress")
int lg_ingress(struct __sk_buff *skb)
{
	struct lg_config *cfg;
	struct ethhdr eth;
	struct lg_key k = {};
	__u32 zero = 0;

	cfg = bpf_map_lookup_elem(&lg_config, &zero);
	if (!cfg)
		return TC_ACT_UNSPEC;
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
		return TC_ACT_UNSPEC;

	fill_key(skb, &k, eth.h_source);

	switch (bpf_ntohs(eth.h_proto)) {
	case ETH_P_IP:
		return ingress_ipv4(skb, cfg, &k);
	case ETH_P_ARP:
		return ingress_arp(skb, cfg, &k);
	case ETH_P_IPV6:
		return ingress_ipv6(skb, cfg, &k);
	case ETH_P_8021Q:
	case ETH_P_8021AD:
		/*
		 * The kernel moves the outer tag out of the frame before TC runs,
		 * so a tag here is a second, stacked one hiding the payload.
		 */
		return deny(cfg, &k, 0, LG_R_VLAN_INBAND);
	}
	if (cfg->flags & LG_F_STRICT_ETHERTYPE)
		return deny(cfg, &k, 0, LG_R_ETHERTYPE);
	return allow(LG_R_PASS_OTHER);
}

/* A server reply on its way to this port: bind, renew or unbind. */
static __always_inline void snoop_reply(struct __sk_buff *skb, __u32 off)
{
	struct dhcp_opts o = {};
	struct lg_pending_req *p;
	struct lg_key k = {};
	struct lg_lease *old;
	struct bootp b;
	__u64 now;

	if (bpf_skb_load_bytes(skb, off, &b, sizeof(b)) < 0 || b.op != BOOTREPLY ||
	    b.htype != BOOTP_HTYPE_ETHER || b.hlen != ETH_ALEN)
		return;
	if (!dhcp_options(skb, off, &o))
		return;
	if (o.msg_type != DHCPACK && o.msg_type != DHCPNAK)
		return;

	fill_key(skb, &k, b.chaddr);
	p = bpf_map_lookup_elem(&lg_pending, &k);
	if (!p) {
		/* Usually a broadcast reply flooded to a port that did not ask. */
		count(LG_R_REPLY_UNSOLICITED);
		return;
	}
	now = now_ns();
	if (p->xid != b.xid || now - p->ts_ns > LG_PENDING_TTL_SECS * NSEC_PER_SEC) {
		count(LG_R_REPLY_STALE);
		return;
	}
	bpf_map_delete_elem(&lg_pending, &k);

	if (o.msg_type == DHCPNAK) {
		old = bpf_map_lookup_elem(&lg_leases, &k);
		if (old) {
			__u32 ip = old->ip;

			bpf_map_delete_elem(&lg_leases, &k);
			count(LG_R_NAK);
			emit(&k, ip, 0, LG_R_NAK, LG_EV_UNBIND);
		}
		return;
	}

	/* An ACK to DHCPINFORM assigns no address. */
	if (!b.yiaddr)
		return;

	__u32 secs = o.lease_be ? bpf_ntohl(o.lease_be) : LG_DEFAULT_LEASE_SECS;
	struct lg_lease l = {
		.ip = b.yiaddr,
		.lease_secs = secs,
		.expires_ns = secs == LG_INFINITE_LEASE ? 0 : now + (__u64)secs * NSEC_PER_SEC,
		.bound_ns = now,
	};

	bpf_map_update_elem(&lg_leases, &k, &l, BPF_ANY);
	count(LG_R_BIND);
	emit(&k, b.yiaddr, secs, LG_R_BIND, LG_EV_BIND);
}

SEC("tcx/egress")
int lg_egress(struct __sk_buff *skb)
{
	struct ethhdr eth;
	struct udphdr udp;
	struct iphdr ip;
	__u32 l4;

	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0 ||
	    eth.h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)) < 0 ||
	    ip.version != 4 || ip.ihl < 5 || ip.protocol != IPPROTO_UDP_ ||
	    (ip.frag_off & bpf_htons(IP_FRAG_OFFSET)))
		return TC_ACT_UNSPEC;
	l4 = ETH_HLEN + ip.ihl * 4;
	if (bpf_skb_load_bytes(skb, l4, &udp, sizeof(udp)) < 0 ||
	    udp.source != bpf_htons(DHCP_SERVER_PORT) ||
	    udp.dest != bpf_htons(DHCP_CLIENT_PORT))
		return TC_ACT_UNSPEC;

	snoop_reply(skb, l4 + sizeof(udp));
	return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
