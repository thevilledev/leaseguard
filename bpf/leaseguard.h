/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/*
 * Types and constants shared by the eBPF datapath and the userspace daemon.
 * Layouts are part of the pinned-map ABI: changing them makes maps pinned by
 * an older version incompatible (run `leaseguard reset` after such a change).
 */
#ifndef LEASEGUARD_H
#define LEASEGUARD_H

#include <linux/types.h>

#define LG_MAC_LEN 6

/* Map names. Pinned maps use the same names under the pin directory. */
#define LG_MAP_LEASES   "lg_leases"
#define LG_MAP_STATIC   "lg_static"
#define LG_MAP_PENDING  "lg_pending"
#define LG_MAP_CONFIG   "lg_config"
#define LG_MAP_COUNTERS "lg_counters"
#define LG_MAP_EVENTS   "lg_events"

#define LG_COUNTER_SLOTS       64         /* lg_counters size; room to add reasons */
#define LG_DEFAULT_EVENT_RATE  100        /* drop events per second per CPU */
#define LG_PENDING_TTL_SECS    60         /* how long a request waits for its reply */
#define LG_DEFAULT_LEASE_SECS  86400      /* used when an ACK carries no lease time */
#define LG_INFINITE_LEASE      0xffffffffu

enum lg_mode {
	LG_MODE_MONITOR = 0, /* count and log violations, drop nothing */
	LG_MODE_ENFORCE = 1, /* drop violations */
};

enum lg_ipv6_policy {
	LG_IPV6_GUARD = 0, /* drop RA/redirects and DHCPv6 server traffic, pass the rest */
	LG_IPV6_DROP  = 1, /* drop all IPv6 from untrusted ports */
	LG_IPV6_ALLOW = 2, /* do not look at IPv6 */
};

enum lg_config_flags {
	LG_F_STRICT_ETHERTYPE = 1u << 0, /* drop ethertypes other than IPv4, ARP and IPv6 */
};

enum lg_event_kind {
	LG_EV_BIND       = 1,
	LG_EV_UNBIND     = 2,
	LG_EV_DROP       = 3,
	LG_EV_WOULD_DROP = 4, /* monitor mode */
};

/*
 * Counter indexes, also used as event reasons. Everything from
 * LG_R_FIRST_VIOLATION on is a violation: dropped in enforce mode, counted
 * and logged in monitor mode.
 */
enum lg_reason {
	LG_R_PASS_IPV4 = 0,      /* IPv4 allowed by a binding */
	LG_R_PASS_ARP,           /* ARP allowed by a binding, or an ARP probe */
	LG_R_PASS_DHCP,          /* DHCP client message allowed */
	LG_R_PASS_IPV6,          /* IPv6 allowed by the IPv6 policy */
	LG_R_PASS_OTHER,         /* other ethertypes */
	LG_R_DHCP_REQUEST,       /* DISCOVER/REQUEST recorded as pending */
	LG_R_BIND,               /* binding created or renewed by an ACK */
	LG_R_RELEASE,            /* binding removed by DHCPRELEASE */
	LG_R_DECLINE,            /* binding removed by DHCPDECLINE */
	LG_R_NAK,                /* binding removed by DHCPNAK */
	LG_R_IMPORT,             /* binding imported from a lease file (by the daemon) */
	LG_R_REPLY_UNSOLICITED,  /* reply reached a port with no matching request */
	LG_R_REPLY_STALE,        /* reply xid did not match, or request too old */

	LG_R_FIRST_VIOLATION,
	LG_R_NO_BINDING = LG_R_FIRST_VIOLATION, /* source MAC has no binding on this port */
	LG_R_IP_MISMATCH,        /* binding exists for the MAC, with another IP */
	LG_R_EXPIRED,            /* binding's lease has run out */
	LG_R_ARP_SHA_MISMATCH,   /* ARP sender MAC differs from the frame's source MAC */
	LG_R_ARP_UNBOUND,        /* ARP sender MAC/IP pair is not bound on this port */
	LG_R_DHCP_SERVER,        /* DHCP server or relay traffic from an untrusted port */
	LG_R_DHCP_CHADDR,        /* DHCP chaddr differs from the frame's source MAC */
	LG_R_DHCP_RELAYED,       /* DHCP request with giaddr set from an untrusted port */
	LG_R_IPV6_ROUTER,        /* router advertisement, redirect or renumbering */
	LG_R_DHCP6_SERVER,       /* DHCPv6 server or relay traffic */
	LG_R_IPV6_POLICY,        /* IPv6 dropped by policy */
	LG_R_IPV6_EXTHDR,        /* IPv6 header chain too long or split across fragments */
	LG_R_VLAN_INBAND,        /* frame still carries a VLAN tag (stacked tags) */
	LG_R_ETHERTYPE,          /* ethertype not allowed in strict mode */
	LG_R_MALFORMED,          /* truncated or invalid headers */

	LG_R_MAX,
};

_Static_assert(LG_R_MAX <= LG_COUNTER_SLOTS, "lg_counters is too small");

enum lg_lease_flags {
	LG_LEASE_IMPORTED = 1u << 0, /* read from the server's lease file, not snooped */
};

/* A port/VLAN/MAC triple. ifindex is the bridge port's ifindex. */
struct lg_key {
	__u32 ifindex;
	__u16 vlan;             /* VLAN ID, 0 for untagged frames */
	__u8  mac[LG_MAC_LEN];
};

/* DHCP-learned binding, value of lg_leases. */
struct lg_lease {
	__u32 ip;               /* network byte order */
	__u32 lease_secs;       /* as granted by the server */
	__u64 expires_ns;       /* CLOCK_BOOTTIME, 0 = never */
	__u64 bound_ns;         /* CLOCK_BOOTTIME of the last ACK */
	__u32 flags;            /* enum lg_lease_flags */
	__u32 _pad;
};

/* Static binding, key of lg_static (value is a __u32, unused). */
struct lg_static_key {
	__u32 ifindex;
	__u16 vlan;
	__u8  mac[LG_MAC_LEN];
	__u32 ip;               /* network byte order */
};

/* Outstanding client request, value of lg_pending. */
struct lg_pending_req {
	__u32 xid;              /* as seen on the wire */
	__u32 _pad;
	__u64 ts_ns;            /* CLOCK_BOOTTIME */
};

/* Value of lg_config[0]. */
struct lg_config {
	__u32 mode;             /* enum lg_mode */
	__u32 ipv6_policy;      /* enum lg_ipv6_policy */
	__u32 flags;            /* enum lg_config_flags */
	__u32 event_rate;       /* drop events per second per CPU, 0 = default */
};

/* Ring buffer record. */
struct lg_event {
	__u64 ts_ns;            /* CLOCK_BOOTTIME */
	__u32 ifindex;
	__u32 ip;               /* network byte order, 0 if not applicable */
	__u32 lease_secs;
	__u16 vlan;
	__u8  mac[LG_MAC_LEN];
	__u16 reason;           /* enum lg_reason */
	__u16 kind;             /* enum lg_event_kind */
};

#endif /* LEASEGUARD_H */
