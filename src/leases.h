/* SPDX-License-Identifier: MIT */
/*
 * DHCP server lease databases, read so that clients holding a lease from
 * before leaseguard started can be bound without waiting for a renewal.
 *
 *   dnsmasq  dnsmasq --dhcp-leasefile (also Incus/LXD, Proxmox SDN)
 *   libvirt  libvirt's <bridge>.status JSON written by its leases helper
 *   kea      Kea memfile CSV (kea-leases4.csv)
 *   isc      ISC dhcpd.leases
 */
#ifndef LG_LEASES_H
#define LG_LEASES_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

enum lease_format {
	LEASES_DNSMASQ,
	LEASES_LIBVIRT,
	LEASES_KEA,
	LEASES_ISC,
};

/* An active IPv4 lease. */
struct lease_rec {
	uint8_t mac[6];
	uint32_t ip;         /* network byte order */
	int64_t expires;     /* unix time, 0 = never */
};

struct lease_source {
	enum lease_format format;
	char path[PATH_MAX];
	struct lease_rec *recs;
	size_t n;
	/* What was loaded, to notice rewrites. */
	bool loaded;
	dev_t dev;
	ino_t ino;
	off_t size;
	struct timespec mtime;
	bool missing_reported;
};

/* "FORMAT:PATH", e.g. "dnsmasq:/var/lib/misc/dnsmasq.leases". */
int lease_source_init(struct lease_source *s, const char *spec);
void lease_source_free(struct lease_source *s);

/* Re-read the file if it changed. Returns 1 if reloaded, 0 if unchanged. */
int lease_source_refresh(struct lease_source *s);

/*
 * Parse a lease database. Records that are not active (released, declined,
 * superseded by a later record for the same address) are left out; expiry
 * is checked at lookup time.
 */
int leases_parse(enum lease_format f, FILE *in, struct lease_rec **out, size_t *n);

/*
 * The lease for exactly this MAC and address, if it is valid at now. If from
 * is not NULL it is set to the source the lease came from.
 */
const struct lease_rec *lease_find(const struct lease_source *srcs, size_t nsrcs,
				   const uint8_t mac[6], uint32_t ip, time_t now,
				   const struct lease_source **from);

const char *lease_format_name(enum lease_format f);

#endif
