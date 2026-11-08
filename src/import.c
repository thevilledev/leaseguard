// SPDX-License-Identifier: MIT
#include "import.h"

#include <string.h>

const char *import_action_name(enum import_action a)
{
	switch (a) {
	case IMPORT_NONE:
		return "no_lease";
	case IMPORT_CONFLICT:
		return "address_bound_elsewhere";
	case IMPORT_OTHER_IP:
		return "bound_to_other_address";
	case IMPORT_CURRENT:
		return "already_bound";
	case IMPORT_INSERT:
		return "insert";
	case IMPORT_REFRESH:
		return "refresh";
	}
	return "unknown";
}

bool import_candidate(unsigned int reason)
{
	/*
	 * ip_mismatch is left out on purpose: the MAC holds a snooped lease
	 * for another address, and only one DHCP binding fits per MAC.
	 */
	return reason == LG_R_NO_BINDING || reason == LG_R_EXPIRED || reason == LG_R_ARP_UNBOUND;
}

static bool same_key(const struct lg_key *a, const struct lg_key *b)
{
	return a->ifindex == b->ifindex && a->vlan == b->vlan && !memcmp(a->mac, b->mac, LG_MAC_LEN);
}

bool import_conflict(const struct lg_binding *snap, size_t n, const struct lg_key *key,
		     uint32_t ip, uint64_t now_boot)
{
	for (size_t i = 0; i < n; i++) {
		const struct lg_binding *b = &snap[i];

		if (b->ip != ip || same_key(&b->key, key))
			continue;
		if (b->is_static || b->expires_ns == 0 || b->expires_ns > now_boot)
			return true;
	}
	return false;
}

enum import_action import_decide(const struct lease_rec *lease, const struct lg_lease *existing,
				 bool conflict, uint64_t now_boot)
{
	if (!lease)
		return IMPORT_NONE;
	if (conflict)
		return IMPORT_CONFLICT;
	if (!existing)
		return IMPORT_INSERT;
	if (existing->ip != lease->ip)
		return IMPORT_OTHER_IP;
	if (existing->expires_ns == 0 || existing->expires_ns > now_boot)
		return IMPORT_CURRENT;
	return IMPORT_REFRESH;
}

void import_value(const struct lease_rec *lease, time_t now_wall, uint64_t now_boot,
		  struct lg_lease *out)
{
	memset(out, 0, sizeof(*out));
	out->ip = lease->ip;
	out->bound_ns = now_boot;
	out->flags = LG_LEASE_IMPORTED;
	if (lease->expires == 0) {
		out->lease_secs = LG_INFINITE_LEASE;
		out->expires_ns = 0;
	} else {
		int64_t left = lease->expires - (int64_t)now_wall;

		if (left < 1)
			left = 1;
		if (left > (int64_t)LG_INFINITE_LEASE - 1)
			left = (int64_t)LG_INFINITE_LEASE - 1;
		out->lease_secs = (uint32_t)left;
		out->expires_ns = now_boot + (uint64_t)left * 1000000000ULL;
	}
}
