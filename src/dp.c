// SPDX-License-Identifier: MIT
#include "dp.h"

#include <errno.h>
#include <linux/magic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "util.h"

/* The compiled datapath, embedded by bpf_obj.S. */
extern const char lg_bpf_obj[];
extern const char lg_bpf_obj_end[];

#define BPFFS        "/sys/fs/bpf"
#define PIN_ROOT     BPFFS "/leaseguard"
#define TC_HANDLE    0x4c47 /* "LG" */
#define TC_PRIORITY  1

static const struct {
	const char *name;
	const char *desc;
} reasons[LG_R_MAX] = {
	[LG_R_PASS_IPV4]         = { "pass_ipv4", "IPv4 allowed by a binding" },
	[LG_R_PASS_ARP]          = { "pass_arp", "ARP allowed by a binding or a probe" },
	[LG_R_PASS_DHCP]         = { "pass_dhcp", "DHCP client message" },
	[LG_R_PASS_IPV6]         = { "pass_ipv6", "IPv6 allowed by policy" },
	[LG_R_PASS_OTHER]        = { "pass_other", "other ethertype" },
	[LG_R_DHCP_REQUEST]      = { "dhcp_request", "DISCOVER/REQUEST recorded" },
	[LG_R_BIND]              = { "bind", "binding created or renewed" },
	[LG_R_RELEASE]           = { "release", "binding removed by DHCPRELEASE" },
	[LG_R_DECLINE]           = { "decline", "binding removed by DHCPDECLINE" },
	[LG_R_NAK]               = { "nak", "binding removed by DHCPNAK" },
	[LG_R_IMPORT]            = { "import", "binding imported from a lease file" },
	[LG_R_REPLY_UNSOLICITED] = { "reply_unsolicited", "reply for a port that did not ask" },
	[LG_R_REPLY_STALE]       = { "reply_stale", "reply with unknown xid or too late" },
	[LG_R_NO_BINDING]        = { "no_binding", "no binding for this MAC on this port" },
	[LG_R_IP_MISMATCH]       = { "ip_mismatch", "MAC is bound to another IP" },
	[LG_R_EXPIRED]           = { "expired", "lease has expired" },
	[LG_R_ARP_SHA_MISMATCH]  = { "arp_sha_mismatch", "ARP sender MAC differs from frame source" },
	[LG_R_ARP_UNBOUND]       = { "arp_unbound", "ARP sender MAC/IP not bound" },
	[LG_R_DHCP_SERVER]       = { "dhcp_server", "DHCP server traffic from an untrusted port" },
	[LG_R_DHCP_CHADDR]       = { "dhcp_chaddr", "DHCP chaddr differs from frame source" },
	[LG_R_DHCP_RELAYED]      = { "dhcp_relayed", "relayed DHCP request from an untrusted port" },
	[LG_R_IPV6_ROUTER]       = { "ipv6_router", "IPv6 RA, redirect or renumbering" },
	[LG_R_DHCP6_SERVER]      = { "dhcp6_server", "DHCPv6 server traffic from an untrusted port" },
	[LG_R_IPV6_POLICY]       = { "ipv6_policy", "IPv6 dropped by policy" },
	[LG_R_IPV6_EXTHDR]       = { "ipv6_exthdr", "IPv6 header chain too long or fragmented" },
	[LG_R_VLAN_INBAND]       = { "vlan_inband", "stacked VLAN tag" },
	[LG_R_ETHERTYPE]         = { "ethertype", "ethertype not allowed (strict mode)" },
	[LG_R_MALFORMED]         = { "malformed", "truncated or invalid headers" },
};

const char *reason_name(unsigned int r)
{
	return r < LG_R_MAX && reasons[r].name ? reasons[r].name : "unknown";
}

const char *reason_desc(unsigned int r)
{
	return r < LG_R_MAX && reasons[r].desc ? reasons[r].desc : "unknown";
}

const char *mode_name(unsigned int mode)
{
	return mode == LG_MODE_ENFORCE ? "enforce" : mode == LG_MODE_MONITOR ? "monitor" : "unknown";
}

const char *ipv6_policy_name(unsigned int p)
{
	switch (p) {
	case LG_IPV6_GUARD:
		return "guard";
	case LG_IPV6_DROP:
		return "drop";
	case LG_IPV6_ALLOW:
		return "allow";
	}
	return "unknown";
}

const char *attach_mode_name(enum lg_attach_mode m)
{
	switch (m) {
	case LG_ATTACH_AUTO:
		return "auto";
	case LG_ATTACH_TCX:
		return "tcx";
	case LG_ATTACH_TC:
		return "tc";
	}
	return "unknown";
}

int lg_pin_dir(char *buf, size_t n, const char *bridge)
{
	int r = snprintf(buf, n, PIN_ROOT "/%s", bridge);

	return r < 0 || (size_t)r >= n ? -ENAMETOOLONG : 0;
}

int lg_ensure_bpffs(void)
{
	struct statfs st;

	if (statfs(BPFFS, &st) == 0 && st.f_type == BPF_FS_MAGIC)
		return 0;
	if (mkdir(BPFFS, 0700) && errno != EEXIST)
		return -errno;
	if (mount("bpf", BPFFS, "bpf", 0, "mode=0700")) {
		int err = -errno;

		log_error("msg=\"cannot mount bpf filesystem\" path=%s error=\"%s\"", BPFFS, strerror(-err));
		return err;
	}
	/*
	 * Usually systemd has mounted it already. If not, this may be a private
	 * mount namespace (ip netns exec remounts /sys), and pins made here are
	 * invisible to `leaseguard bindings` run from elsewhere.
	 */
	log_warn("msg=\"mounted a bpf filesystem; if this is a private mount namespace (as under "
		 "ip netns exec), other processes cannot see the pinned state, so prefer nsenter --net\" "
		 "path=%s", BPFFS);
	return 0;
}

static int mkdir_p(const char *path)
{
	char buf[4096];
	size_t len = strlen(path);

	if (len >= sizeof(buf))
		return -ENAMETOOLONG;
	memcpy(buf, path, len + 1);
	for (char *p = buf + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(buf, 0700) && errno != EEXIST)
			return -errno;
		*p = '/';
	}
	if (mkdir(buf, 0700) && errno != EEXIST)
		return -errno;
	return 0;
}

/* Set while doing things that are expected to fail, such as removing tc filters that may not exist. */
static bool libbpf_quiet;

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	int lvl = level == LIBBPF_WARN ? LGL_WARN : LGL_TRACE;
	char buf[1024];
	size_t n;

	if (libbpf_quiet || lvl > lg_log_level)
		return 0;
	vsnprintf(buf, sizeof(buf), fmt, ap);
	n = strlen(buf);
	while (n && buf[n - 1] == '\n')
		buf[--n] = '\0';
	for (char *p = buf; *p; p++)
		if (*p == '"')
			*p = '\'';
	if (n)
		lg_log(lvl, "msg=\"%s\"", buf);
	return 0;
}

static int map_fd(struct bpf_object *obj, const char *name)
{
	struct bpf_map *m = bpf_object__find_map_by_name(obj, name);

	return m ? bpf_map__fd(m) : -ENOENT;
}

int dp_load(struct lg_dp *dp, const char *pin_dir)
{
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.object_name = "leaseguard",
		.pin_root_path = pin_dir,
	);
	int err;

	memset(dp, 0, sizeof(*dp));
	libbpf_set_print(libbpf_print);

	err = mkdir_p(pin_dir);
	if (err) {
		log_error("msg=\"cannot create pin directory\" path=%s error=\"%s\"", pin_dir, strerror(-err));
		return err;
	}

	dp->obj = bpf_object__open_mem(lg_bpf_obj, (size_t)(lg_bpf_obj_end - lg_bpf_obj), &opts);
	if (!dp->obj) {
		err = -errno;
		log_error("msg=\"cannot open eBPF object\" error=\"%s\"", strerror(-err));
		return err;
	}
	err = bpf_object__load(dp->obj);
	if (err) {
		log_error("msg=\"cannot load eBPF object\" error=\"%s\" hint=\"maps pinned in %s by "
			  "another leaseguard version are not reused; `leaseguard reset` removes them\"",
			  strerror(-err), pin_dir);
		bpf_object__close(dp->obj);
		dp->obj = NULL;
		return err;
	}

	dp->ingress = bpf_object__find_program_by_name(dp->obj, "lg_ingress");
	dp->egress = bpf_object__find_program_by_name(dp->obj, "lg_egress");
	dp->maps.leases = map_fd(dp->obj, LG_MAP_LEASES);
	dp->maps.statics = map_fd(dp->obj, LG_MAP_STATIC);
	dp->maps.pending = map_fd(dp->obj, LG_MAP_PENDING);
	dp->maps.config = map_fd(dp->obj, LG_MAP_CONFIG);
	dp->maps.counters = map_fd(dp->obj, LG_MAP_COUNTERS);
	dp->events_fd = map_fd(dp->obj, LG_MAP_EVENTS);
	if (!dp->ingress || !dp->egress || dp->maps.leases < 0 || dp->maps.statics < 0 ||
	    dp->maps.pending < 0 || dp->maps.config < 0 || dp->maps.counters < 0 ||
	    dp->events_fd < 0) {
		log_error("msg=\"eBPF object is missing programs or maps\"");
		dp_unload(dp);
		return -ENOENT;
	}
	return 0;
}

void dp_unload(struct lg_dp *dp)
{
	/* Pinned maps live on in the bpf filesystem. */
	bpf_object__close(dp->obj);
	dp->obj = NULL;
}

static int attach_tcx(struct lg_dp *dp, int ifindex, struct lg_attachment *a)
{
	/* BPF_F_BEFORE without a relative program puts us first in line. */
	LIBBPF_OPTS(bpf_tcx_opts, opts, .flags = BPF_F_BEFORE);
	int err;

	a->in = bpf_program__attach_tcx(dp->ingress, ifindex, &opts);
	if (!a->in)
		return -errno;
	a->eg = bpf_program__attach_tcx(dp->egress, ifindex, &opts);
	if (!a->eg) {
		err = -errno;
		bpf_link__destroy(a->in);
		a->in = NULL;
		return err;
	}
	return 0;
}

/* Remove our tc filters if present; absent filters or devices are fine. */
static void detach_tc(int ifindex)
{
	const enum bpf_tc_attach_point points[] = { BPF_TC_INGRESS, BPF_TC_EGRESS };

	libbpf_quiet = true;
	for (size_t i = 0; i < ARRAY_SIZE(points); i++) {
		LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = points[i]);
		LIBBPF_OPTS(bpf_tc_opts, opts, .handle = TC_HANDLE, .priority = TC_PRIORITY);

		bpf_tc_detach(&hook, &opts);
	}
	libbpf_quiet = false;
}

static int attach_tc(struct lg_dp *dp, int ifindex)
{
	const struct {
		enum bpf_tc_attach_point point;
		struct bpf_program *prog;
	} hooks[] = {
		{ BPF_TC_INGRESS, dp->ingress },
		{ BPF_TC_EGRESS, dp->egress },
	};
	LIBBPF_OPTS(bpf_tc_hook, qdisc, .ifindex = ifindex,
		    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
	int err;

	/* clsact may already exist, owned by someone else; it is left in place. */
	err = bpf_tc_hook_create(&qdisc);
	if (err && err != -EEXIST)
		return err;

	for (size_t i = 0; i < ARRAY_SIZE(hooks); i++) {
		LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = hooks[i].point);
		LIBBPF_OPTS(bpf_tc_opts, opts,
			.handle = TC_HANDLE,
			.priority = TC_PRIORITY,
			.flags = BPF_TC_F_REPLACE,
			.prog_fd = bpf_program__fd(hooks[i].prog),
		);

		err = bpf_tc_attach(&hook, &opts);
		if (err) {
			detach_tc(ifindex);
			return err;
		}
	}
	return 0;
}

int dp_attach(struct lg_dp *dp, int ifindex, enum lg_attach_mode mode,
	      struct lg_attachment *out)
{
	int err;

	memset(out, 0, sizeof(*out));
	out->ifindex = ifindex;

	if (mode != LG_ATTACH_TC) {
		err = attach_tcx(dp, ifindex, out);
		if (!err) {
			out->mode = LG_ATTACH_TCX;
			/* Filters from an earlier tc-mode run would run twice. */
			detach_tc(ifindex);
			return 0;
		}
		/* Kernels before 6.6 do not know the TCX attach types. */
		if (mode == LG_ATTACH_TCX || (err != -EINVAL && err != -EOPNOTSUPP))
			return err;
		log_info("msg=\"TCX not available, using tc\" ifindex=%d error=\"%s\"", ifindex,
			 strerror(-err));
	}

	err = attach_tc(dp, ifindex);
	if (err)
		return err;
	out->mode = LG_ATTACH_TC;
	return 0;
}

void dp_detach(struct lg_attachment *a)
{
	if (a->mode == LG_ATTACH_TCX) {
		bpf_link__destroy(a->in);
		bpf_link__destroy(a->eg);
	} else if (a->mode == LG_ATTACH_TC) {
		detach_tc(a->ifindex);
	}
	memset(a, 0, sizeof(*a));
}

void dp_detach_stale_tc(int ifindex)
{
	detach_tc(ifindex);
}

static const struct {
	const char *name;
	size_t off;
} pinned_maps[] = {
	{ LG_MAP_LEASES, offsetof(struct lg_maps, leases) },
	{ LG_MAP_STATIC, offsetof(struct lg_maps, statics) },
	{ LG_MAP_PENDING, offsetof(struct lg_maps, pending) },
	{ LG_MAP_CONFIG, offsetof(struct lg_maps, config) },
	{ LG_MAP_COUNTERS, offsetof(struct lg_maps, counters) },
};

int maps_open_pinned(struct lg_maps *m, const char *pin_dir)
{
	char path[4096];

	for (size_t i = 0; i < ARRAY_SIZE(pinned_maps); i++)
		*(int *)((char *)m + pinned_maps[i].off) = -1;

	for (size_t i = 0; i < ARRAY_SIZE(pinned_maps); i++) {
		int fd;

		snprintf(path, sizeof(path), "%s/%s", pin_dir, pinned_maps[i].name);
		fd = bpf_obj_get(path);
		if (fd < 0) {
			int err = -errno;

			maps_close(m);
			return err;
		}
		*(int *)((char *)m + pinned_maps[i].off) = fd;
	}
	return 0;
}

void maps_close(struct lg_maps *m)
{
	for (size_t i = 0; i < ARRAY_SIZE(pinned_maps); i++) {
		int *fd = (int *)((char *)m + pinned_maps[i].off);

		if (*fd >= 0)
			close(*fd);
		*fd = -1;
	}
}

int maps_set_config(const struct lg_maps *m, const struct lg_config *c)
{
	uint32_t zero = 0;

	return bpf_map_update_elem(m->config, &zero, c, BPF_ANY) ? -errno : 0;
}

int maps_get_config(const struct lg_maps *m, struct lg_config *c)
{
	uint32_t zero = 0;

	return bpf_map_lookup_elem(m->config, &zero, c) ? -errno : 0;
}

int maps_counters(const struct lg_maps *m, uint64_t out[LG_R_MAX])
{
	int ncpus = libbpf_num_possible_cpus();
	uint64_t *vals;

	if (ncpus <= 0)
		return ncpus ? ncpus : -EINVAL;
	vals = calloc((size_t)ncpus, sizeof(*vals));
	if (!vals)
		return -ENOMEM;
	for (uint32_t r = 0; r < LG_R_MAX; r++) {
		out[r] = 0;
		if (bpf_map_lookup_elem(m->counters, &r, vals))
			continue;
		for (int c = 0; c < ncpus; c++)
			out[r] += vals[c];
	}
	free(vals);
	return 0;
}

/* Collect all keys first: deleting while iterating a hash map can skip entries. */
static int map_keys(int fd, size_t key_size, void **out, size_t *n)
{
	uint8_t cur[64], next[64];
	void *keys = NULL;
	size_t cap = 0, cnt = 0;
	void *prev = NULL;

	while (bpf_map_get_next_key(fd, prev, next) == 0) {
		if (grow(&keys, &cap, cnt + 1, key_size)) {
			free(keys);
			return -ENOMEM;
		}
		memcpy((char *)keys + cnt * key_size, next, key_size);
		cnt++;
		memcpy(cur, next, key_size);
		prev = cur;
	}
	*out = keys;
	*n = cnt;
	return 0;
}

int maps_bindings(const struct lg_maps *m, struct lg_binding **out, size_t *n)
{
	struct lg_binding *res = NULL;
	struct lg_static_key *sk = NULL;
	struct lg_key *lk = NULL;
	size_t nlk = 0, nsk = 0, cap = 0, cnt = 0;
	int err;

	err = map_keys(m->leases, sizeof(*lk), (void **)&lk, &nlk);
	if (err)
		return err;
	err = map_keys(m->statics, sizeof(*sk), (void **)&sk, &nsk);
	if (err) {
		free(lk);
		return err;
	}
	if (grow((void **)&res, &cap, nlk + nsk + 1, sizeof(*res))) {
		free(lk);
		free(sk);
		return -ENOMEM;
	}
	for (size_t i = 0; i < nlk; i++) {
		struct lg_lease l;

		if (bpf_map_lookup_elem(m->leases, &lk[i], &l))
			continue;  /* expired and collected meanwhile */
		res[cnt++] = (struct lg_binding){
			.key = lk[i],
			.ip = l.ip,
			.lease_secs = l.lease_secs,
			.expires_ns = l.expires_ns,
			.bound_ns = l.bound_ns,
			.flags = l.flags,
		};
	}
	for (size_t i = 0; i < nsk; i++) {
		struct lg_binding *b = &res[cnt++];

		memset(b, 0, sizeof(*b));
		b->key.ifindex = sk[i].ifindex;
		b->key.vlan = sk[i].vlan;
		memcpy(b->key.mac, sk[i].mac, LG_MAC_LEN);
		b->ip = sk[i].ip;
		b->is_static = true;
	}
	free(lk);
	free(sk);
	*out = res;
	*n = cnt;
	return 0;
}

int maps_counter_add(const struct lg_maps *m, uint32_t reason, uint64_t delta)
{
	int ncpus = libbpf_num_possible_cpus();
	uint64_t *vals;
	int err = 0;

	if (ncpus <= 0)
		return ncpus ? ncpus : -EINVAL;
	vals = calloc((size_t)ncpus, sizeof(*vals));
	if (!vals)
		return -ENOMEM;
	/* Only userspace writes this slot, so the read-modify-write cannot race. */
	if (bpf_map_lookup_elem(m->counters, &reason, vals) == 0) {
		vals[0] += delta;
		if (bpf_map_update_elem(m->counters, &reason, vals, BPF_EXIST))
			err = -errno;
	} else {
		err = -errno;
	}
	free(vals);
	return err;
}

int maps_sync_static(const struct lg_maps *m, const struct lg_static_key *want, size_t n)
{
	struct lg_static_key *have = NULL;
	size_t nhave = 0;
	uint32_t one = 1;
	int err;

	err = map_keys(m->statics, sizeof(*have), (void **)&have, &nhave);
	if (err)
		return err;
	for (size_t i = 0; i < nhave; i++) {
		bool keep = false;

		for (size_t j = 0; j < n && !keep; j++)
			keep = memcmp(&have[i], &want[j], sizeof(*have)) == 0;
		if (!keep)
			bpf_map_delete_elem(m->statics, &have[i]);
	}
	free(have);
	for (size_t j = 0; j < n; j++) {
		if (bpf_map_update_elem(m->statics, &want[j], &one, BPF_ANY))
			return -errno;
	}
	return 0;
}

int maps_gc(const struct lg_maps *m, uint64_t grace_secs,
	    bool (*alive)(int ifindex, void *arg), void *arg, struct lg_gc_stats *st)
{
	const uint64_t ttl = (uint64_t)LG_PENDING_TTL_SECS * 1000000000ULL;
	const uint64_t now = boot_ns();
	struct lg_key *keys = NULL;
	size_t n = 0;
	int err;

	memset(st, 0, sizeof(*st));

	err = map_keys(m->leases, sizeof(*keys), (void **)&keys, &n);
	if (err)
		return err;
	for (size_t i = 0; i < n; i++) {
		struct lg_lease l;

		if (bpf_map_lookup_elem(m->leases, &keys[i], &l))
			continue;
		if (alive((int)keys[i].ifindex, arg) &&
		    !(l.expires_ns && now > l.expires_ns + grace_secs * 1000000000ULL))
			continue;
		if (!bpf_map_delete_elem(m->leases, &keys[i]))
			st->leases++;
	}
	free(keys);

	err = map_keys(m->pending, sizeof(*keys), (void **)&keys, &n);
	if (err)
		return err;
	for (size_t i = 0; i < n; i++) {
		struct lg_pending_req p;

		if (bpf_map_lookup_elem(m->pending, &keys[i], &p))
			continue;
		if (alive((int)keys[i].ifindex, arg) && now - p.ts_ns <= ttl)
			continue;
		if (!bpf_map_delete_elem(m->pending, &keys[i]))
			st->pending++;
	}
	free(keys);
	return 0;
}

int lg_unpin(const char *pin_dir)
{
	char path[4096];
	int err = 0;

	for (size_t i = 0; i < ARRAY_SIZE(pinned_maps); i++) {
		snprintf(path, sizeof(path), "%s/%s", pin_dir, pinned_maps[i].name);
		if (unlink(path) && errno != ENOENT && !err)
			err = -errno;
	}
	if (rmdir(pin_dir) && errno != ENOENT && !err)
		err = -errno;
	return err;
}
