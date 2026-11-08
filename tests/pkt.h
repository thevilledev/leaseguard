/* SPDX-License-Identifier: MIT */
/* Small frame builders for the datapath tests. Addresses are host order. */
#ifndef LG_TEST_PKT_H
#define LG_TEST_PKT_H

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#define PKT_MAX 1600

struct pkt {
	uint8_t b[PKT_MAX];
	size_t len;
};

static const uint8_t BCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static inline void put(struct pkt *p, const void *d, size_t n)
{
	memcpy(p->b + p->len, d, n);
	p->len += n;
}

static inline void put8(struct pkt *p, uint8_t v) { put(p, &v, 1); }
static inline void put16(struct pkt *p, uint16_t v) { v = htons(v); put(p, &v, 2); }
static inline void put32(struct pkt *p, uint32_t v) { v = htonl(v); put(p, &v, 4); }

static inline void set16(struct pkt *p, size_t off, uint16_t v)
{
	v = htons(v);
	memcpy(p->b + off, &v, 2);
}

static inline void eth(struct pkt *p, const uint8_t *dst, const uint8_t *src, uint16_t proto)
{
	p->len = 0;
	put(p, dst, 6);
	put(p, src, 6);
	put16(p, proto);
}

/* IPv4 header; returns its offset so lengths can be fixed up later. */
static inline size_t ipv4(struct pkt *p, uint32_t src, uint32_t dst, uint8_t proto,
			  uint16_t frag)
{
	size_t off = p->len;

	put8(p, 0x45);
	put8(p, 0);
	put16(p, 0);        /* total length, fixed up */
	put16(p, 0x1234);
	put16(p, frag);
	put8(p, 64);
	put8(p, proto);
	put16(p, 0);
	put32(p, src);
	put32(p, dst);
	return off;
}

static inline size_t udp(struct pkt *p, uint16_t sport, uint16_t dport)
{
	size_t off = p->len;

	put16(p, sport);
	put16(p, dport);
	put16(p, 0);        /* length, fixed up */
	put16(p, 0);
	return off;
}

static inline void fix_ipv4_udp(struct pkt *p, size_t ip_off, size_t udp_off)
{
	set16(p, ip_off + 2, (uint16_t)(p->len - ip_off));
	if (udp_off)
		set16(p, udp_off + 4, (uint16_t)(p->len - udp_off));
}

/* An IPv4 UDP datagram with a few payload bytes. */
static inline void udp4(struct pkt *p, const uint8_t *smac, uint32_t src, uint32_t dst,
			uint16_t sport, uint16_t dport)
{
	size_t ip_off, udp_off;

	eth(p, BCAST, smac, 0x0800);
	ip_off = ipv4(p, src, dst, 17, 0);
	udp_off = udp(p, sport, dport);
	put32(p, 0xdeadbeef);
	fix_ipv4_udp(p, ip_off, udp_off);
}

struct dhcp_msg {
	uint8_t op;           /* 1 request, 2 reply */
	uint8_t type;         /* option 53, 0 to omit */
	uint32_t xid;
	const uint8_t *chaddr;
	uint32_t ciaddr, yiaddr, giaddr;
	int64_t lease;        /* option 51, -1 to omit */
	int pad_before;       /* PAD options before option 53 */
	int no_magic;         /* plain BOOTP */
};

/*
 * A DHCP message in a frame from smac. Requests go 0.0.0.0:68 ->
 * 255.255.255.255:67, replies 10.0.0.1:67 -> 255.255.255.255:68.
 */
static inline void dhcp(struct pkt *p, const uint8_t *smac, const struct dhcp_msg *m)
{
	int reply = m->op == 2;
	size_t ip_off, udp_off;
	uint8_t zero[192] = {0};
	uint8_t chaddr[16] = {0};

	eth(p, BCAST, smac, 0x0800);
	ip_off = ipv4(p, reply ? 0x0a000001 : 0, 0xffffffff, 17, 0);
	udp_off = udp(p, reply ? 67 : 68, reply ? 68 : 67);

	put8(p, m->op);
	put8(p, 1);           /* htype ethernet */
	put8(p, 6);           /* hlen */
	put8(p, 0);
	put(p, &m->xid, 4);   /* xid is opaque, keep wire order */
	put16(p, 0);
	put16(p, 0x8000);
	put32(p, m->ciaddr);
	put32(p, m->yiaddr);
	put32(p, 0);
	put32(p, m->giaddr);
	memcpy(chaddr, m->chaddr, 6);
	put(p, chaddr, 16);
	put(p, zero, sizeof(zero)); /* sname + file */
	if (!m->no_magic) {
		put32(p, 0x63825363);
		for (int i = 0; i < m->pad_before; i++)
			put8(p, 0);
		if (m->type) {
			put8(p, 53);
			put8(p, 1);
			put8(p, m->type);
		}
		if (m->lease >= 0) {
			put8(p, 51);
			put8(p, 4);
			put32(p, (uint32_t)m->lease);
		}
		put8(p, 54);          /* server identifier */
		put8(p, 4);
		put32(p, 0x0a000001);
		put8(p, 255);
	}
	fix_ipv4_udp(p, ip_off, udp_off);
}

static inline void arp(struct pkt *p, const uint8_t *smac, uint16_t oper,
		       const uint8_t *sha, uint32_t spa, uint32_t tpa)
{
	static const uint8_t zero[6];

	eth(p, BCAST, smac, 0x0806);
	put16(p, 1);
	put16(p, 0x0800);
	put8(p, 6);
	put8(p, 4);
	put16(p, oper);
	put(p, sha, 6);
	put32(p, spa);
	put(p, zero, 6);
	put32(p, tpa);
}

/* IPv6 frame: fixed header with next header nh, then body as given. */
static inline void ipv6(struct pkt *p, const uint8_t *smac, uint8_t nh,
			const void *body, size_t len)
{
	static const uint8_t src[16] = { 0xfe, 0x80, [15] = 1 };
	static const uint8_t dst[16] = { 0xff, 0x02, [15] = 1 };

	eth(p, BCAST, smac, 0x86dd);
	put32(p, 0x60000000);
	put16(p, (uint16_t)len);
	put8(p, nh);
	put8(p, 255);
	put(p, src, 16);
	put(p, dst, 16);
	put(p, body, len);
}

#endif
