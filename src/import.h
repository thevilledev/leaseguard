/* SPDX-License-Identifier: MIT */
/*
 * Lease import: when traffic from a port is dropped (or would be, in monitor
 * mode) because its MAC/IP pair has no binding, and the DHCP server's lease
 * file shows that exact pair as a valid lease, the daemon adds the binding.
 *
 * This covers clients that got their lease before leaseguard started, or
 * renewed it while leaseguard was stopped. The event comes from the port
 * itself, so port and VLAN are exactly what the datapath will look up.
 */
#ifndef LG_IMPORT_H
#define LG_IMPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "dp.h"
#include "leases.h"

enum import_action {
	IMPORT_NONE,      /* no valid lease for this MAC and address */
	IMPORT_CONFLICT,  /* the address is bound to another port, VLAN or MAC */
	IMPORT_OTHER_IP,  /* this port/VLAN/MAC is bound to another address */
	IMPORT_CURRENT,   /* already bound, nothing to do */
	IMPORT_INSERT,    /* new binding */
	IMPORT_REFRESH,   /* same address, binding expired: renew it from the lease */
};

const char *import_action_name(enum import_action a);

/* Whether an event with this reason can be fixed by an import. */
bool import_candidate(unsigned int reason);

/*
 * Is ip bound, and still valid, for anything other than key? Static
 * bindings always count. snap is a recent snapshot of all bindings.
 */
bool import_conflict(const struct lg_binding *snap, size_t n, const struct lg_key *key,
		     uint32_t ip, uint64_t now_boot);

enum import_action import_decide(const struct lease_rec *lease, const struct lg_lease *existing,
				 bool conflict, uint64_t now_boot);

/* The binding to write for lease, which lease_find() has found valid at now_wall. */
void import_value(const struct lease_rec *lease, time_t now_wall, uint64_t now_boot,
		  struct lg_lease *out);

#endif
