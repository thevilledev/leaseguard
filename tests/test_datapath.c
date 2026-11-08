// SPDX-License-Identifier: MIT
/*
 * Datapath tests: load the eBPF object through the verifier and run crafted
 * frames through lg_ingress/lg_egress with BPF_PROG_TEST_RUN. Needs root.
 *
 * Test runs use the loopback device, so every binding here is keyed on
 * ifindex 1 and VLAN 0.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/pkt_cls.h>

#include "../bpf/leaseguard.h"
#include "pkt.h"

#define PASS     TC_ACT_UNSPEC
#define DROP     TC_ACT_SHOT
#define REJECTED (-1000)  /* the kernel would not inject the frame */
#define LO       1

static int prog_in, prog_eg;
static int m_leases, m_static, m_pending, m_config, m_counters;
static int ncpus;
static int failures, checks;
static const char *current;

static const uint8_t MAC_A[6] = { 0x02, 0, 0, 0, 0, 0xaa };
static const uint8_t MAC_B[6] = { 0x02, 0, 0, 0, 0, 0xbb };

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))

static void fail(int line, const char *fmt, ...)
{
	va_list ap;

	failures++;
	fprintf(stderr, "FAIL %s (line %d): ", current, line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

#define CHECK(cond, ...) do { checks++; if (!(cond)) fail(__LINE__, __VA_ARGS__); } while (0)
#define EXPECT_EQ(got, want) do { long long g_ = (long long)(got), w_ = (long long)(want); \
	checks++; if (g_ != w_) fail(__LINE__, "%s = %lld, want %lld", #got, g_, w_); } while (0)

static uint64_t boot_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_BOOTTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int run(int prog, const struct pkt *p)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = p->b,
		.data_size_in = (__u32)p->len,
		.repeat = 1,
	);

	if (bpf_prog_test_run_opts(prog, &opts)) {
		/*
		 * Newer kernels refuse to inject some malformed frames (an IPv4
		 * ethertype without a full IPv4 header, for instance).
		 */
		if (errno == EINVAL)
			return REJECTED;
		fprintf(stderr, "test run failed: %s\n", strerror(errno));
		exit(2);
	}
	return (int)opts.retval;
}

static void clear_map(int fd, size_t key_size)
{
	uint8_t key[64], next[64];

	while (bpf_map_get_next_key(fd, NULL, next) == 0) {
		memcpy(key, next, key_size);
		bpf_map_delete_elem(fd, key);
	}
}

static void set_config(uint32_t mode, uint32_t ipv6, uint32_t flags)
{
	struct lg_config c = { .mode = mode, .ipv6_policy = ipv6, .flags = flags };
	uint32_t zero = 0;

	bpf_map_update_elem(m_config, &zero, &c, BPF_ANY);
}

static void reset(const char *name, uint32_t mode)
{
	uint64_t zeros[1024] = {0};

	current = name;
	clear_map(m_leases, sizeof(struct lg_key));
	clear_map(m_static, sizeof(struct lg_static_key));
	clear_map(m_pending, sizeof(struct lg_key));
	for (uint32_t i = 0; i < LG_R_MAX; i++)
		bpf_map_update_elem(m_counters, &i, zeros, BPF_ANY);
	set_config(mode, LG_IPV6_GUARD, 0);
}

static uint64_t counter(uint32_t reason)
{
	uint64_t vals[1024] = {0}, sum = 0;

	bpf_map_lookup_elem(m_counters, &reason, vals);
	for (int i = 0; i < ncpus; i++)
		sum += vals[i];
	return sum;
}

static struct lg_key key(const uint8_t *mac)
{
	struct lg_key k = { .ifindex = LO };

	memcpy(k.mac, mac, 6);
	return k;
}

static void add_lease(const uint8_t *mac, uint32_t ip, int64_t ttl_secs)
{
	struct lg_key k = key(mac);
	struct lg_lease l = {
		.ip = htonl(ip),
		.lease_secs = 3600,
		.bound_ns = boot_ns(),
	};

	if (ttl_secs)
		l.expires_ns = boot_ns() + ttl_secs * 1000000000LL;
	bpf_map_update_elem(m_leases, &k, &l, BPF_ANY);
}

static int get_lease(const uint8_t *mac, struct lg_lease *l)
{
	struct lg_key k = key(mac);

	return bpf_map_lookup_elem(m_leases, &k, l) == 0;
}

static int has_pending(const uint8_t *mac, uint32_t xid)
{
	struct lg_key k = key(mac);
	struct lg_pending_req p;

	return bpf_map_lookup_elem(m_pending, &k, &p) == 0 && p.xid == xid;
}

/* --- IPv4 source guard ------------------------------------------------ */

static void test_ipv4_source_guard(void)
{
	struct pkt p;

	reset("ipv4: unbound source is dropped", LG_MODE_ENFORCE);
	udp4(&p, MAC_A, IP(10, 0, 0, 5), IP(10, 0, 0, 1), 4000, 53);
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_NO_BINDING), 1);

	reset("ipv4: bound source passes", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 5), 600);
	EXPECT_EQ(run(prog_in, &p), PASS);
	EXPECT_EQ(counter(LG_R_PASS_IPV4), 1);

	reset("ipv4: bound MAC with another IP is dropped", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 6), 600);
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_IP_MISMATCH), 1);

	reset("ipv4: bound IP from another MAC is dropped", LG_MODE_ENFORCE);
	add_lease(MAC_B, IP(10, 0, 0, 5), 600);
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_NO_BINDING), 1);

	reset("ipv4: expired lease is dropped", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 5), -5);
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_EXPIRED), 1);

	reset("ipv4: infinite lease passes", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 5), 0);
	EXPECT_EQ(run(prog_in, &p), PASS);

	reset("ipv4: static binding passes", LG_MODE_ENFORCE);
	{
		struct lg_static_key sk = { .ifindex = LO, .ip = htonl(IP(10, 0, 0, 5)) };
		uint32_t one = 1;

		memcpy(sk.mac, MAC_A, 6);
		bpf_map_update_elem(m_static, &sk, &one, BPF_ANY);
	}
	EXPECT_EQ(run(prog_in, &p), PASS);

	reset("ipv4: static binding next to a lease for another IP", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 9), 600);
	{
		struct lg_static_key sk = { .ifindex = LO, .ip = htonl(IP(10, 0, 0, 5)) };
		uint32_t one = 1;

		memcpy(sk.mac, MAC_A, 6);
		bpf_map_update_elem(m_static, &sk, &one, BPF_ANY);
	}
	EXPECT_EQ(run(prog_in, &p), PASS);

	reset("ipv4: monitor mode passes violations and counts them", LG_MODE_MONITOR);
	EXPECT_EQ(run(prog_in, &p), PASS);
	EXPECT_EQ(counter(LG_R_NO_BINDING), 1);

	reset("ipv4: non-first fragment is checked by source", LG_MODE_ENFORCE);
	{
		size_t ip_off;

		eth(&p, BCAST, MAC_A, 0x0800);
		ip_off = ipv4(&p, IP(10, 0, 0, 5), IP(10, 0, 0, 1), 17, 0x00b9);
		put32(&p, 0);
		fix_ipv4_udp(&p, ip_off, 0);
	}
	EXPECT_EQ(run(prog_in, &p), DROP);
	add_lease(MAC_A, IP(10, 0, 0, 5), 600);
	EXPECT_EQ(run(prog_in, &p), PASS);

	reset("ipv4: bad header length is malformed", LG_MODE_ENFORCE);
	udp4(&p, MAC_A, IP(10, 0, 0, 5), IP(10, 0, 0, 1), 4000, 53);
	p.b[14] = 0x44;
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_MALFORMED), 1);

	/* The kernel will not inject a frame cut inside the IPv4 header. */
	reset("ipv4: truncated UDP header is malformed", LG_MODE_ENFORCE);
	udp4(&p, MAC_A, IP(10, 0, 0, 5), IP(10, 0, 0, 1), 4000, 53);
	p.len = 14 + 20 + 4;
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_MALFORMED), 1);
}

/* --- DHCP snooping ---------------------------------------------------- */

static void test_dhcp_client_side(void)
{
	struct pkt p;
	struct dhcp_msg m = { .op = 1, .type = 1, .xid = 0x11223344, .chaddr = MAC_A, .lease = -1 };

	reset("dhcp: DISCOVER passes and is recorded", LG_MODE_ENFORCE);
	dhcp(&p, MAC_A, &m);
	EXPECT_EQ(run(prog_in, &p), PASS);
	CHECK(has_pending(MAC_A, m.xid), "no pending entry after DISCOVER");
	EXPECT_EQ(counter(LG_R_PASS_DHCP), 1);

	reset("dhcp: REQUEST passes and is recorded", LG_MODE_ENFORCE);
	m.type = 3;
	dhcp(&p, MAC_A, &m);
	EXPECT_EQ(run(prog_in, &p), PASS);
	CHECK(has_pending(MAC_A, m.xid), "no pending entry after REQUEST");

	reset("dhcp: message type behind padding is found", LG_MODE_ENFORCE);
	m.pad_before = 40;
	dhcp(&p, MAC_A, &m);
	EXPECT_EQ(run(prog_in, &p), PASS);
	CHECK(has_pending(MAC_A, m.xid), "no pending entry after padded REQUEST");
	m.pad_before = 0;

	reset("dhcp: chaddr must match the source MAC", LG_MODE_ENFORCE);
	m.chaddr = MAC_B;
	dhcp(&p, MAC_A, &m);
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_DHCP_CHADDR), 1);
	CHECK(!has_pending(MAC_B, m.xid), "spoofed chaddr was recorded");
	m.chaddr = MAC_A;

	reset("dhcp: relayed request from an untrusted port is dropped", LG_MODE_ENFORCE);
	m.giaddr = IP(10, 9, 9, 9);
	dhcp(&p, MAC_A, &m);
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_DHCP_RELAYED), 1);
	m.giaddr = 0;

	reset("dhcp: plain BOOTP request passes without being recorded", LG_MODE_ENFORCE);
	m.no_magic = 1;
	dhcp(&p, MAC_A, &m);
	EXPECT_EQ(run(prog_in, &p), PASS);
	CHECK(!has_pending(MAC_A, m.xid), "BOOTP request was recorded");
	m.no_magic = 0;

	reset("dhcp: RELEASE removes the client's binding", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 5), 600);
	m.type = 7;
	m.ciaddr = IP(10, 0, 0, 5);
	dhcp(&p, MAC_A, &m);
	EXPECT_EQ(run(prog_in, &p), PASS);
	{
		struct lg_lease l;

		CHECK(!get_lease(MAC_A, &l), "binding survived RELEASE");
	}
	EXPECT_EQ(counter(LG_R_RELEASE), 1);

	reset("dhcp: RELEASE for another address keeps the binding", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 5), 600);
	m.ciaddr = IP(10, 0, 0, 77);
	dhcp(&p, MAC_A, &m);
	EXPECT_EQ(run(prog_in, &p), PASS);
	{
		struct lg_lease l;

		CHECK(get_lease(MAC_A, &l), "binding removed by mismatched RELEASE");
	}

	reset("dhcp: DECLINE removes the client's binding", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 5), 600);
	m.type = 4;
	m.ciaddr = 0;
	dhcp(&p, MAC_A, &m);
	EXPECT_EQ(run(prog_in, &p), PASS);
	{
		struct lg_lease l;

		CHECK(!get_lease(MAC_A, &l), "binding survived DECLINE");
	}
}

static void test_dhcp_server_guard(void)
{
	struct pkt p;
	struct dhcp_msg m = { .op = 2, .type = 2, .xid = 7, .chaddr = MAC_B,
			      .yiaddr = IP(10, 0, 0, 50), .lease = 600 };

	reset("dhcp: OFFER from an untrusted port is dropped", LG_MODE_ENFORCE);
	dhcp(&p, MAC_A, &m);
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_DHCP_SERVER), 1);

	reset("dhcp: ACK from an untrusted port is dropped even when bound", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 1), 600);
	m.type = 5;
	dhcp(&p, MAC_A, &m);
	/* the rogue reply's source is 10.0.0.1, bound to MAC_A */
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_DHCP_SERVER), 1);

	reset("dhcp: BOOTREPLY sent from the client port is dropped", LG_MODE_ENFORCE);
	m.op = 2;
	dhcp(&p, MAC_A, &m);
	/* swap ports so it looks like a client message carrying a reply */
	set16(&p, 14 + 20, 68);
	set16(&p, 14 + 20 + 2, 67);
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_DHCP_SERVER), 1);
}

static void test_dhcp_reply_snooping(void)
{
	struct pkt req, ack;
	struct lg_lease l;
	struct dhcp_msg mreq = { .op = 1, .type = 3, .xid = 0xabcdef01, .chaddr = MAC_A, .lease = -1 };
	struct dhcp_msg mack = { .op = 2, .type = 5, .xid = 0xabcdef01, .chaddr = MAC_A,
				 .yiaddr = IP(10, 0, 0, 42), .lease = 600 };
	static const uint8_t SERVER[6] = { 0x02, 0, 0, 0, 0, 0x01 };
	uint64_t before;

	reset("snoop: ACK for a recorded request creates a binding", LG_MODE_ENFORCE);
	dhcp(&req, MAC_A, &mreq);
	dhcp(&ack, SERVER, &mack);
	EXPECT_EQ(run(prog_in, &req), PASS);
	before = boot_ns();
	EXPECT_EQ(run(prog_eg, &ack), PASS);
	CHECK(get_lease(MAC_A, &l), "no binding after ACK");
	EXPECT_EQ(ntohl(l.ip), IP(10, 0, 0, 42));
	EXPECT_EQ(l.lease_secs, 600);
	CHECK(l.expires_ns >= before + 600ULL * 1000000000ULL &&
	      l.expires_ns <= boot_ns() + 600ULL * 1000000000ULL, "expiry out of range");
	CHECK(!has_pending(MAC_A, mreq.xid), "pending entry kept after ACK");
	EXPECT_EQ(counter(LG_R_BIND), 1);
	{
		struct pkt d;

		udp4(&d, MAC_A, IP(10, 0, 0, 42), IP(10, 0, 0, 1), 1000, 2000);
		EXPECT_EQ(run(prog_in, &d), PASS);
	}

	reset("snoop: ACK without a request does not bind", LG_MODE_ENFORCE);
	EXPECT_EQ(run(prog_eg, &ack), PASS);
	CHECK(!get_lease(MAC_A, &l), "unsolicited ACK created a binding");
	EXPECT_EQ(counter(LG_R_REPLY_UNSOLICITED), 1);

	reset("snoop: ACK with another xid does not bind", LG_MODE_ENFORCE);
	EXPECT_EQ(run(prog_in, &req), PASS);
	mack.xid = 0x55555555;
	dhcp(&ack, SERVER, &mack);
	EXPECT_EQ(run(prog_eg, &ack), PASS);
	CHECK(!get_lease(MAC_A, &l), "ACK with wrong xid created a binding");
	EXPECT_EQ(counter(LG_R_REPLY_STALE), 1);
	mack.xid = mreq.xid;

	reset("snoop: OFFER keeps the request pending", LG_MODE_ENFORCE);
	EXPECT_EQ(run(prog_in, &req), PASS);
	mack.type = 2;
	dhcp(&ack, SERVER, &mack);
	EXPECT_EQ(run(prog_eg, &ack), PASS);
	CHECK(!get_lease(MAC_A, &l), "OFFER created a binding");
	CHECK(has_pending(MAC_A, mreq.xid), "OFFER consumed the pending request");
	mack.type = 5;

	reset("snoop: ACK without lease time uses the default", LG_MODE_ENFORCE);
	EXPECT_EQ(run(prog_in, &req), PASS);
	mack.lease = -1;
	dhcp(&ack, SERVER, &mack);
	EXPECT_EQ(run(prog_eg, &ack), PASS);
	CHECK(get_lease(MAC_A, &l), "no binding after ACK without lease time");
	EXPECT_EQ(l.lease_secs, LG_DEFAULT_LEASE_SECS);
	mack.lease = 600;

	reset("snoop: infinite lease never expires", LG_MODE_ENFORCE);
	EXPECT_EQ(run(prog_in, &req), PASS);
	mack.lease = 0xffffffffLL;
	dhcp(&ack, SERVER, &mack);
	EXPECT_EQ(run(prog_eg, &ack), PASS);
	CHECK(get_lease(MAC_A, &l), "no binding after infinite ACK");
	EXPECT_EQ(l.expires_ns, 0);
	mack.lease = 600;

	reset("snoop: renewal replaces the address", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 7), 600);
	EXPECT_EQ(run(prog_in, &req), PASS);
	dhcp(&ack, SERVER, &mack);
	EXPECT_EQ(run(prog_eg, &ack), PASS);
	CHECK(get_lease(MAC_A, &l) && ntohl(l.ip) == IP(10, 0, 0, 42), "binding not replaced");

	reset("snoop: NAK removes the binding", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 7), 600);
	EXPECT_EQ(run(prog_in, &req), PASS);
	mack.type = 6;
	mack.yiaddr = 0;
	dhcp(&ack, SERVER, &mack);
	EXPECT_EQ(run(prog_eg, &ack), PASS);
	CHECK(!get_lease(MAC_A, &l), "binding survived NAK");
	EXPECT_EQ(counter(LG_R_NAK), 1);
	mack.type = 5;
	mack.yiaddr = IP(10, 0, 0, 42);

	reset("snoop: ACK to INFORM (no yiaddr) does not bind", LG_MODE_ENFORCE);
	EXPECT_EQ(run(prog_in, &req), PASS);
	mack.yiaddr = 0;
	dhcp(&ack, SERVER, &mack);
	EXPECT_EQ(run(prog_eg, &ack), PASS);
	CHECK(!get_lease(MAC_A, &l), "INFORM ACK created a binding");
	mack.yiaddr = IP(10, 0, 0, 42);

	reset("snoop: works in monitor mode too", LG_MODE_MONITOR);
	EXPECT_EQ(run(prog_in, &req), PASS);
	dhcp(&ack, SERVER, &mack);
	EXPECT_EQ(run(prog_eg, &ack), PASS);
	CHECK(get_lease(MAC_A, &l), "no binding in monitor mode");

	reset("snoop: egress ignores everything that is not a reply", LG_MODE_ENFORCE);
	{
		struct pkt d;

		udp4(&d, MAC_A, IP(10, 0, 0, 5), IP(10, 0, 0, 1), 1000, 2000);
		EXPECT_EQ(run(prog_eg, &d), PASS);
		arp(&d, MAC_A, 1, MAC_A, IP(10, 0, 0, 5), IP(10, 0, 0, 1));
		EXPECT_EQ(run(prog_eg, &d), PASS);
	}
}

/* --- ARP inspection --------------------------------------------------- */

static void test_arp(void)
{
	struct pkt p;

	reset("arp: unbound sender is dropped", LG_MODE_ENFORCE);
	arp(&p, MAC_A, 2, MAC_A, IP(10, 0, 0, 1), IP(10, 0, 0, 9));
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_ARP_UNBOUND), 1);

	reset("arp: bound sender passes", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 5), 600);
	arp(&p, MAC_A, 1, MAC_A, IP(10, 0, 0, 5), IP(10, 0, 0, 1));
	EXPECT_EQ(run(prog_in, &p), PASS);
	EXPECT_EQ(counter(LG_R_PASS_ARP), 1);

	reset("arp: bound MAC claiming another IP is dropped", LG_MODE_ENFORCE);
	add_lease(MAC_A, IP(10, 0, 0, 5), 600);
	arp(&p, MAC_A, 2, MAC_A, IP(10, 0, 0, 1), IP(10, 0, 0, 9));
	EXPECT_EQ(run(prog_in, &p), DROP);

	reset("arp: sender MAC must match the frame", LG_MODE_ENFORCE);
	add_lease(MAC_B, IP(10, 0, 0, 5), 600);
	arp(&p, MAC_A, 2, MAC_B, IP(10, 0, 0, 5), IP(10, 0, 0, 9));
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_ARP_SHA_MISMATCH), 1);

	reset("arp: probe with zero sender address passes", LG_MODE_ENFORCE);
	arp(&p, MAC_A, 1, MAC_A, 0, IP(10, 0, 0, 5));
	EXPECT_EQ(run(prog_in, &p), PASS);

	reset("arp: non-IPv4 ARP is malformed", LG_MODE_ENFORCE);
	arp(&p, MAC_A, 1, MAC_A, 0, IP(10, 0, 0, 5));
	set16(&p, 14 + 2, 0x86dd);
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_MALFORMED), 1);
}

/* --- IPv6 ------------------------------------------------------------- */

static void test_ipv6(void)
{
	struct pkt p;
	uint8_t ra[16] = { 134, 0 };
	uint8_t rs[8] = { 133, 0 };
	uint8_t redirect[40] = { 137, 0 };
	uint8_t echo[8] = { 128, 0 };
	uint8_t hop_ra[8 + 16] = { 58, 0, 5, 2, 0, 0, 1, 0, 134 };
	uint8_t chain_ra[8 + 8 + 16] = { 60, 0, 1, 4, 0, 0, 0, 0,  58, 0, 1, 4, 0, 0, 0, 0,  134 };
	uint8_t frag_first_ra[8 + 16] = { 58, 0, 0x00, 0x01, 1, 2, 3, 4, 134 };
	uint8_t frag_later[8 + 8] = { 58, 0, 0x00, 0xb9, 1, 2, 3, 4 };
	uint8_t frag_split[8] = { 0, 0, 0x00, 0x01, 1, 2, 3, 4 };
	uint8_t dhcp6_adv[8] = { 0x02, 0x23, 0x02, 0x22, 0, 8, 0, 0 };  /* 547 -> 546 */
	uint8_t dhcp6_sol[8] = { 0x02, 0x22, 0x02, 0x23, 0, 8, 0, 0 };  /* 546 -> 547 */
	uint8_t many_hdrs[9 * 8 + 8] = {0};

	reset("ipv6: router advertisement is dropped", LG_MODE_ENFORCE);
	ipv6(&p, MAC_A, 58, ra, sizeof(ra));
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_IPV6_ROUTER), 1);

	reset("ipv6: redirect is dropped", LG_MODE_ENFORCE);
	ipv6(&p, MAC_A, 58, redirect, sizeof(redirect));
	EXPECT_EQ(run(prog_in, &p), DROP);

	reset("ipv6: router solicitation and echo pass", LG_MODE_ENFORCE);
	ipv6(&p, MAC_A, 58, rs, sizeof(rs));
	EXPECT_EQ(run(prog_in, &p), PASS);
	ipv6(&p, MAC_A, 58, echo, sizeof(echo));
	EXPECT_EQ(run(prog_in, &p), PASS);

	reset("ipv6: RA behind a hop-by-hop header is dropped", LG_MODE_ENFORCE);
	ipv6(&p, MAC_A, 0, hop_ra, sizeof(hop_ra));
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_IPV6_ROUTER), 1);

	reset("ipv6: RA behind two destination-options headers is dropped", LG_MODE_ENFORCE);
	ipv6(&p, MAC_A, 60, chain_ra, sizeof(chain_ra));
	EXPECT_EQ(run(prog_in, &p), DROP);

	reset("ipv6: RA in a first fragment is dropped", LG_MODE_ENFORCE);
	ipv6(&p, MAC_A, 44, frag_first_ra, sizeof(frag_first_ra));
	EXPECT_EQ(run(prog_in, &p), DROP);

	reset("ipv6: later fragment passes", LG_MODE_ENFORCE);
	ipv6(&p, MAC_A, 44, frag_later, sizeof(frag_later));
	EXPECT_EQ(run(prog_in, &p), PASS);

	reset("ipv6: header chain split across fragments is dropped", LG_MODE_ENFORCE);
	ipv6(&p, MAC_A, 44, frag_split, sizeof(frag_split));
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_IPV6_EXTHDR), 1);

	reset("ipv6: too many extension headers is dropped", LG_MODE_ENFORCE);
	for (int i = 0; i < 9; i++)
		many_hdrs[i * 8] = 60;   /* next header: destination options */
	many_hdrs[8 * 8] = 59;
	ipv6(&p, MAC_A, 60, many_hdrs, sizeof(many_hdrs));
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_IPV6_EXTHDR), 1);

	reset("ipv6: DHCPv6 advertise is dropped, solicit passes", LG_MODE_ENFORCE);
	ipv6(&p, MAC_A, 17, dhcp6_adv, sizeof(dhcp6_adv));
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_DHCP6_SERVER), 1);
	ipv6(&p, MAC_A, 17, dhcp6_sol, sizeof(dhcp6_sol));
	EXPECT_EQ(run(prog_in, &p), PASS);

	reset("ipv6: drop policy drops everything", LG_MODE_ENFORCE);
	set_config(LG_MODE_ENFORCE, LG_IPV6_DROP, 0);
	ipv6(&p, MAC_A, 58, echo, sizeof(echo));
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_IPV6_POLICY), 1);

	reset("ipv6: allow policy passes router advertisements", LG_MODE_ENFORCE);
	set_config(LG_MODE_ENFORCE, LG_IPV6_ALLOW, 0);
	ipv6(&p, MAC_A, 58, ra, sizeof(ra));
	EXPECT_EQ(run(prog_in, &p), PASS);
}

/* --- Other ethertypes ------------------------------------------------- */

static void test_ethertypes(void)
{
	struct pkt p;

	reset("ether: stacked VLAN tag is dropped", LG_MODE_ENFORCE);
	eth(&p, BCAST, MAC_A, 0x8100);
	put16(&p, 10);
	put16(&p, 0x0800);
	put32(&p, 0);
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_VLAN_INBAND), 1);

	reset("ether: other ethertypes pass by default", LG_MODE_ENFORCE);
	eth(&p, BCAST, MAC_A, 0x88cc);
	put32(&p, 0);
	EXPECT_EQ(run(prog_in, &p), PASS);
	EXPECT_EQ(counter(LG_R_PASS_OTHER), 1);

	reset("ether: strict mode drops other ethertypes", LG_MODE_ENFORCE);
	set_config(LG_MODE_ENFORCE, LG_IPV6_GUARD, LG_F_STRICT_ETHERTYPE);
	EXPECT_EQ(run(prog_in, &p), DROP);
	EXPECT_EQ(counter(LG_R_ETHERTYPE), 1);
}

/* --- Events ----------------------------------------------------------- */

struct ev_count {
	int bind, drop, would_drop;
};

static int on_event(void *ctx, void *data, size_t size)
{
	struct ev_count *c = ctx;
	const struct lg_event *e = data;

	if (size < sizeof(*e))
		return 0;
	if (e->kind == LG_EV_BIND)
		c->bind++;
	else if (e->kind == LG_EV_DROP)
		c->drop++;
	else if (e->kind == LG_EV_WOULD_DROP)
		c->would_drop++;
	return 0;
}

static void test_events(struct bpf_object *obj)
{
	struct bpf_map *m = bpf_object__find_map_by_name(obj, LG_MAP_EVENTS);
	struct ev_count c = {0};
	struct ring_buffer *rb;
	struct pkt p;
	struct lg_config cfg = { .mode = LG_MODE_ENFORCE, .event_rate = 5 };
	uint32_t zero = 0;

	rb = ring_buffer__new(bpf_map__fd(m), on_event, &c, NULL);
	CHECK(rb != NULL, "ring buffer: %s", strerror(errno));
	if (!rb)
		return;
	ring_buffer__consume(rb);
	memset(&c, 0, sizeof(c));

	reset("events: drops are reported, rate limited per CPU", LG_MODE_ENFORCE);
	bpf_map_update_elem(m_config, &zero, &cfg, BPF_ANY);
	sleep(1);   /* earlier tests used up this second's budget */
	udp4(&p, MAC_A, IP(10, 0, 0, 5), IP(10, 0, 0, 1), 4000, 53);
	for (int i = 0; i < 50; i++)
		run(prog_in, &p);
	ring_buffer__consume(rb);
	CHECK(c.drop >= 1 && c.drop <= 5 * ncpus, "got %d drop events, want 1..%d", c.drop, 5 * ncpus);
	EXPECT_EQ(counter(LG_R_NO_BINDING), 50);

	reset("events: monitor mode reports would-drop", LG_MODE_MONITOR);
	memset(&c, 0, sizeof(c));
	sleep(1);   /* let the rate limit window roll over */
	run(prog_in, &p);
	ring_buffer__consume(rb);
	EXPECT_EQ(c.would_drop, 1);
	EXPECT_EQ(c.drop, 0);

	ring_buffer__free(rb);
}

int main(void)
{
	struct bpf_object *obj;
	struct bpf_map *map;
	const char *path = getenv("LG_BPF_OBJ") ?: "build/leaseguard.bpf.o";
	int err;

	if (geteuid() != 0) {
		fprintf(stderr, "test_datapath needs root (BPF_PROG_TEST_RUN)\n");
		return 77;
	}
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	ncpus = libbpf_num_possible_cpus();
	if (ncpus <= 0 || ncpus > 1024) {
		fprintf(stderr, "unsupported CPU count %d\n", ncpus);
		return 2;
	}

	obj = bpf_object__open_file(path, NULL);
	if (!obj) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return 2;
	}
	/* Keep tests away from the pin directory. */
	bpf_object__for_each_map(map, obj)
		bpf_map__set_pin_path(map, NULL);
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load %s: %s\n", path, strerror(-err));
		return 2;
	}

	prog_in = bpf_program__fd(bpf_object__find_program_by_name(obj, "lg_ingress"));
	prog_eg = bpf_program__fd(bpf_object__find_program_by_name(obj, "lg_egress"));
	m_leases = bpf_map__fd(bpf_object__find_map_by_name(obj, LG_MAP_LEASES));
	m_static = bpf_map__fd(bpf_object__find_map_by_name(obj, LG_MAP_STATIC));
	m_pending = bpf_map__fd(bpf_object__find_map_by_name(obj, LG_MAP_PENDING));
	m_config = bpf_map__fd(bpf_object__find_map_by_name(obj, LG_MAP_CONFIG));
	m_counters = bpf_map__fd(bpf_object__find_map_by_name(obj, LG_MAP_COUNTERS));

	test_ipv4_source_guard();
	test_dhcp_client_side();
	test_dhcp_server_guard();
	test_dhcp_reply_snooping();
	test_arp();
	test_ipv6();
	test_ethertypes();
	test_events(obj);

	bpf_object__close(obj);
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
