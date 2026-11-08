/* SPDX-License-Identifier: MIT */
/*
 * Static bindings file, one binding per line:
 *
 *     # port      mac                ip          [vlan]
 *     tap100i0    bc:24:11:aa:bb:cc  10.0.0.5
 *     tap101i0    bc:24:11:00:11:22  10.0.0.6    20
 *
 * Ports are bridge port names, resolved to ifindexes whenever ports change.
 */
#ifndef LG_STATICS_H
#define LG_STATICS_H

#include <net/if.h>
#include <stddef.h>
#include <stdint.h>

struct static_entry {
	char port[IF_NAMESIZE];
	uint8_t mac[6];
	uint32_t ip;    /* network byte order */
	uint16_t vlan;
};

/* Parse path into a new array. Errors are logged with line numbers. */
int statics_load(const char *path, struct static_entry **out, size_t *n);

#endif
