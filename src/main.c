// SPDX-License-Identifier: MIT
/*
 * leaseguard: DHCP snooping, IPv4 source guard and ARP inspection for the
 * ports of a Linux bridge, enforced by eBPF.
 */
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "daemon.h"
#include "dp.h"
#include "util.h"

#ifndef LG_VERSION
#define LG_VERSION "dev"
#endif

static const char usage_text[] =
	"usage: leaseguard <command> [options]\n"
	"\n"
	"commands:\n"
	"  run       protect a bridge (runs in the foreground)\n"
	"  bindings  list current bindings\n"
	"  stats     show mode and per-reason counters\n"
	"  mode      switch a running instance: leaseguard mode monitor|enforce\n"
	"  reset     remove pinned state (bindings, counters, config)\n"
	"  version   print the version\n"
	"\n"
	"every command except version takes:\n"
	"  -b, --bridge NAME      the bridge (pin directory /sys/fs/bpf/leaseguard/NAME)\n"
	"      --pin-dir DIR      use another pin directory\n"
	"\n"
	"run options:\n"
	"  -t, --trusted PORT     port left unchecked: uplink, DHCP server; glob patterns\n"
	"                         allowed; repeat for more ports\n"
	"  -m, --mode MODE        monitor (default) or enforce\n"
	"      --ipv6 POLICY      guard (default): drop RA and DHCPv6 server traffic;\n"
	"                         drop: drop all IPv6; allow: leave IPv6 alone\n"
	"  -s, --static FILE      static bindings: PORT MAC IP [VLAN] per line;\n"
	"                         re-read on SIGHUP\n"
	"  -l, --leases FMT:PATH  DHCP server lease file to import existing leases\n"
	"                         from; FMT is dnsmasq, libvirt, kea or isc;\n"
	"                         repeat for more files\n"
	"      --attach MODE      auto (default), tcx or tc\n"
	"      --strict-ethertypes  drop ethertypes other than IPv4, ARP and IPv6\n"
	"      --event-rate N     drop log lines per second per CPU (default 100)\n"
	"      --interval SECS    port resync and garbage collection period (default 15)\n"
	"  -v, --verbose          debug logging; twice to include libbpf\n";

static void usage(FILE *f)
{
	fputs(usage_text, f);
}

enum {
	OPT_PIN_DIR = 256,
	OPT_IPV6,
	OPT_ATTACH,
	OPT_STRICT,
	OPT_EVENT_RATE,
	OPT_INTERVAL,
	OPT_FORCE,
};

#define MAX_LEASE_FILES 16

static const struct option long_opts[] = {
	{ "bridge", required_argument, NULL, 'b' },
	{ "pin-dir", required_argument, NULL, OPT_PIN_DIR },
	{ "trusted", required_argument, NULL, 't' },
	{ "mode", required_argument, NULL, 'm' },
	{ "ipv6", required_argument, NULL, OPT_IPV6 },
	{ "static", required_argument, NULL, 's' },
	{ "leases", required_argument, NULL, 'l' },
	{ "attach", required_argument, NULL, OPT_ATTACH },
	{ "strict-ethertypes", no_argument, NULL, OPT_STRICT },
	{ "event-rate", required_argument, NULL, OPT_EVENT_RATE },
	{ "interval", required_argument, NULL, OPT_INTERVAL },
	{ "force", no_argument, NULL, OPT_FORCE },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ 0 },
};

struct cli {
	struct run_opts run;
	char pin_buf[4096];
	const char *lease_specs[MAX_LEASE_FILES];
	bool force;
};

static int parse_mode(const char *s, unsigned int *out)
{
	if (!strcmp(s, "monitor"))
		*out = LG_MODE_MONITOR;
	else if (!strcmp(s, "enforce"))
		*out = LG_MODE_ENFORCE;
	else
		return -EINVAL;
	return 0;
}

static int parse_args(int argc, char **argv, struct cli *c)
{
	struct run_opts *o = &c->run;
	int opt;

	o->mode = LG_MODE_MONITOR;
	o->ipv6 = LG_IPV6_GUARD;
	o->attach = LG_ATTACH_AUTO;
	o->interval_secs = 15;

	optind = 1;
	o->lease_specs = c->lease_specs;
	while ((opt = getopt_long(argc, argv, "b:t:m:s:l:vh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'b':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "bridge name too long: %s\n", optarg);
				return -EINVAL;
			}
			o->bridge = optarg;
			break;
		case OPT_PIN_DIR:
			o->pin_dir = optarg;
			break;
		case 't':
			o->trusted = realloc(o->trusted, (o->ntrusted + 1) * sizeof(*o->trusted));
			if (!o->trusted)
				return -ENOMEM;
			o->trusted[o->ntrusted++] = optarg;
			break;
		case 'm':
			if (parse_mode(optarg, &o->mode)) {
				fprintf(stderr, "--mode: want monitor or enforce, got %s\n", optarg);
				return -EINVAL;
			}
			break;
		case OPT_IPV6:
			if (!strcmp(optarg, "guard"))
				o->ipv6 = LG_IPV6_GUARD;
			else if (!strcmp(optarg, "drop"))
				o->ipv6 = LG_IPV6_DROP;
			else if (!strcmp(optarg, "allow"))
				o->ipv6 = LG_IPV6_ALLOW;
			else {
				fprintf(stderr, "--ipv6: want guard, drop or allow, got %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 's':
			o->static_file = optarg;
			break;
		case 'l':
			if (o->nlease_specs >= MAX_LEASE_FILES) {
				fprintf(stderr, "--leases: at most %d files\n", MAX_LEASE_FILES);
				return -EINVAL;
			}
			c->lease_specs[o->nlease_specs++] = optarg;
			break;
		case OPT_ATTACH:
			if (!strcmp(optarg, "auto"))
				o->attach = LG_ATTACH_AUTO;
			else if (!strcmp(optarg, "tcx"))
				o->attach = LG_ATTACH_TCX;
			else if (!strcmp(optarg, "tc"))
				o->attach = LG_ATTACH_TC;
			else {
				fprintf(stderr, "--attach: want auto, tcx or tc, got %s\n", optarg);
				return -EINVAL;
			}
			break;
		case OPT_STRICT:
			o->strict_ethertypes = true;
			break;
		case OPT_EVENT_RATE:
			if (parse_u32(optarg, &o->event_rate) || o->event_rate == 0) {
				fprintf(stderr, "--event-rate: want a positive number, got %s\n", optarg);
				return -EINVAL;
			}
			break;
		case OPT_INTERVAL:
			if (parse_u32(optarg, &o->interval_secs) || o->interval_secs == 0) {
				fprintf(stderr, "--interval: want a positive number of seconds, got %s\n", optarg);
				return -EINVAL;
			}
			break;
		case OPT_FORCE:
			c->force = true;
			break;
		case 'v':
			if (lg_log_level < LGL_TRACE)
				lg_log_level++;
			break;
		case 'h':
			usage(stdout);
			exit(0);
		default:
			usage(stderr);
			return -EINVAL;
		}
	}

	if (!o->pin_dir) {
		if (!o->bridge) {
			fprintf(stderr, "--bridge (or --pin-dir) is required\n");
			return -EINVAL;
		}
		if (lg_pin_dir(c->pin_buf, sizeof(c->pin_buf), o->bridge))
			return -ENAMETOOLONG;
		o->pin_dir = c->pin_buf;
	}
	return 0;
}

static int open_maps(const struct cli *c, struct lg_maps *m)
{
	int err = maps_open_pinned(m, c->run.pin_dir);

	if (err)
		fprintf(stderr, "cannot open pinned maps in %s: %s\n"
			"is `leaseguard run` running, or has it run, for this bridge?\n",
			c->run.pin_dir, strerror(-err));
	return err;
}

static int cmp_binding(const void *a, const void *b)
{
	const struct lg_binding *x = a, *y = b;

	if (x->key.ifindex != y->key.ifindex)
		return x->key.ifindex < y->key.ifindex ? -1 : 1;
	if (x->key.vlan != y->key.vlan)
		return x->key.vlan < y->key.vlan ? -1 : 1;
	return memcmp(x->key.mac, y->key.mac, LG_MAC_LEN);
}

static int cmd_bindings(struct cli *c)
{
	struct lg_binding *b = NULL;
	struct lg_maps m;
	uint64_t now = boot_ns();
	size_t n = 0;
	int err;

	err = open_maps(c, &m);
	if (err)
		return err;
	err = maps_bindings(&m, &b, &n);
	maps_close(&m);
	if (err) {
		fprintf(stderr, "cannot read bindings: %s\n", strerror(-err));
		return err;
	}
	qsort(b, n, sizeof(*b), cmp_binding);

	printf("%-16s %-5s %-17s %-15s %-7s %s\n", "PORT", "VLAN", "MAC", "IP", "SOURCE", "EXPIRES");
	for (size_t i = 0; i < n; i++) {
		char port[IF_NAMESIZE + 8], mac[18], ip[16], exp[32];

		if (!if_indextoname(b[i].key.ifindex, port))
			snprintf(port, sizeof(port), "if%u", b[i].key.ifindex);
		fmt_mac(b[i].key.mac, mac);
		fmt_ipv4(b[i].ip, ip);
		if (b[i].is_static || !b[i].expires_ns) {
			snprintf(exp, sizeof(exp), "never");
		} else if (b[i].expires_ns <= now) {
			snprintf(exp, sizeof(exp), "expired");
		} else {
			char d[24];

			fmt_duration((b[i].expires_ns - now) / 1000000000ULL, d, sizeof(d));
			snprintf(exp, sizeof(exp), "in %s", d);
		}
		printf("%-16s %-5u %-17s %-15s %-7s %s\n", port, b[i].key.vlan, mac, ip,
		       b[i].is_static ? "static" :
		       b[i].flags & LG_LEASE_IMPORTED ? "import" : "dhcp", exp);
	}
	free(b);
	return 0;
}

static int cmd_stats(struct cli *c)
{
	uint64_t cnt[LG_R_MAX];
	struct lg_config cfg;
	struct lg_binding *b = NULL;
	struct lg_maps m;
	size_t n = 0, nstatic = 0;
	int err;

	err = open_maps(c, &m);
	if (err)
		return err;
	err = maps_get_config(&m, &cfg);
	if (!err)
		err = maps_counters(&m, cnt);
	if (!err)
		err = maps_bindings(&m, &b, &n);
	maps_close(&m);
	if (err) {
		fprintf(stderr, "cannot read state: %s\n", strerror(-err));
		return err;
	}
	for (size_t i = 0; i < n; i++)
		nstatic += b[i].is_static;
	free(b);

	printf("mode      %s\n", mode_name(cfg.mode));
	printf("ipv6      %s\n", ipv6_policy_name(cfg.ipv6_policy));
	printf("bindings  %zu dhcp, %zu static\n\n", n - nstatic, nstatic);
	printf("%-18s %12s  %s\n", "COUNTER", "VALUE", "MEANING");
	for (unsigned int r = 0; r < LG_R_MAX; r++) {
		if (r == LG_R_FIRST_VIOLATION)
			printf("%-18s %12s  %s\n", "", "", cfg.mode == LG_MODE_ENFORCE ?
			       "violations (dropped)" : "violations (monitor mode: passed)");
		printf("%-18s %12llu  %s\n", reason_name(r), (unsigned long long)cnt[r], reason_desc(r));
	}
	return 0;
}

static int cmd_mode(struct cli *c, int argc, char **argv)
{
	struct lg_config cfg;
	struct lg_maps m;
	unsigned int mode;
	int err;

	if (optind >= argc || parse_mode(argv[optind], &mode)) {
		fprintf(stderr, "usage: leaseguard mode monitor|enforce --bridge NAME\n");
		return -EINVAL;
	}
	err = open_maps(c, &m);
	if (err)
		return err;
	err = maps_get_config(&m, &cfg);
	if (!err) {
		cfg.mode = mode;
		err = maps_set_config(&m, &cfg);
	}
	maps_close(&m);
	if (err) {
		fprintf(stderr, "cannot update mode: %s\n", strerror(-err));
		return err;
	}
	printf("mode %s\n", mode_name(mode));
	return 0;
}

static int cmd_reset(struct cli *c)
{
	int lock, err;

	lock = lg_lock(c->run.pin_dir);
	if (lock == -ENOENT) {
		printf("nothing to reset in %s\n", c->run.pin_dir);
		return 0;
	}
	if (lock == -EBUSY && !c->force) {
		fprintf(stderr, "leaseguard is running on %s; stop it first (or use --force)\n",
			c->run.pin_dir);
		return lock;
	}
	err = lg_unpin(c->run.pin_dir);
	if (lock >= 0)
		close(lock);
	if (err) {
		fprintf(stderr, "cannot remove %s: %s\n", c->run.pin_dir, strerror(-err));
		return err;
	}
	printf("removed %s\n", c->run.pin_dir);
	return 0;
}

int main(int argc, char **argv)
{
	struct cli c = {0};
	const char *cmd;
	int err;

	if (argc < 2) {
		usage(stderr);
		return 2;
	}
	cmd = argv[1];
	if (!strcmp(cmd, "version") || !strcmp(cmd, "--version")) {
		printf("leaseguard %s\n", LG_VERSION);
		return 0;
	}
	if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
		usage(stdout);
		return 0;
	}

	err = parse_args(argc - 1, argv + 1, &c);
	if (err)
		return 2;

	if (!strcmp(cmd, "run")) {
		if (!c.run.bridge) {
			fprintf(stderr, "run: --bridge is required\n");
			return 2;
		}
		err = daemon_run(&c.run);
	} else if (!strcmp(cmd, "bindings")) {
		err = cmd_bindings(&c);
	} else if (!strcmp(cmd, "stats")) {
		err = cmd_stats(&c);
	} else if (!strcmp(cmd, "mode")) {
		err = cmd_mode(&c, argc - 1, argv + 1);
	} else if (!strcmp(cmd, "reset")) {
		err = cmd_reset(&c);
	} else {
		fprintf(stderr, "unknown command: %s\n", cmd);
		usage(stderr);
		return 2;
	}
	free(c.run.trusted);
	return err ? 1 : 0;
}
