/* SPDX-License-Identifier: MIT */
#ifndef LG_DAEMON_H
#define LG_DAEMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dp.h"

struct run_opts {
	const char *bridge;
	const char **trusted;      /* port names or fnmatch(3) patterns */
	size_t ntrusted;
	unsigned int mode;         /* enum lg_mode */
	unsigned int ipv6;         /* enum lg_ipv6_policy */
	const char *static_file;   /* optional, re-read on SIGHUP */
	const char **lease_specs;  /* "FORMAT:PATH" lease files to import from */
	size_t nlease_specs;
	enum lg_attach_mode attach;
	bool strict_ethertypes;
	uint32_t event_rate;
	const char *pin_dir;
	unsigned int interval_secs;  /* resync and GC period */
};

int daemon_run(const struct run_opts *o);

/*
 * Take the per-pin-directory lock that keeps two daemons off the same maps.
 * Returns the lock fd, -EBUSY if another process holds it.
 */
int lg_lock(const char *pin_dir);

#endif
