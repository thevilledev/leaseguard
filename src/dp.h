/* SPDX-License-Identifier: MIT */
/* Loading, attaching and map access for the eBPF datapath. */
#ifndef LG_DP_H
#define LG_DP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "leaseguard.h"

struct bpf_object;
struct bpf_program;
struct bpf_link;

/* File descriptors of the pinned maps. */
struct lg_maps {
	int leases;
	int statics;
	int pending;
	int config;
	int counters;
};

struct lg_dp {
	struct bpf_object *obj;
	struct bpf_program *ingress;
	struct bpf_program *egress;
	struct lg_maps maps;   /* owned by obj */
	int events_fd;
};

enum lg_attach_mode {
	LG_ATTACH_AUTO,
	LG_ATTACH_TCX,         /* bpf links, kernel 6.6+, detached when closed */
	LG_ATTACH_TC,          /* clsact + cls_bpf, stays until removed */
};

struct lg_attachment {
	int ifindex;
	enum lg_attach_mode mode;
	struct bpf_link *in;   /* TCX only */
	struct bpf_link *eg;
};

struct lg_binding {
	struct lg_key key;
	uint32_t ip;           /* network byte order */
	bool is_static;
	uint32_t flags;        /* enum lg_lease_flags */
	uint32_t lease_secs;
	uint64_t expires_ns;   /* CLOCK_BOOTTIME, 0 = never */
	uint64_t bound_ns;
};

struct lg_gc_stats {
	unsigned int leases;
	unsigned int pending;
};

/* Default pin directory for a bridge. */
int lg_pin_dir(char *buf, size_t n, const char *bridge);

/* Make sure a bpf filesystem is mounted at /sys/fs/bpf. */
int lg_ensure_bpffs(void);

/* Load the embedded object, reusing or creating pinned maps in pin_dir. */
int dp_load(struct lg_dp *dp, const char *pin_dir);
void dp_unload(struct lg_dp *dp);

/*
 * Attach lg_ingress and lg_egress to ifindex. With LG_ATTACH_AUTO, TCX is
 * tried first and tc is used when the kernel lacks TCX; out->mode tells which.
 */
int dp_attach(struct lg_dp *dp, int ifindex, enum lg_attach_mode mode,
	      struct lg_attachment *out);
void dp_detach(struct lg_attachment *a);

/* Remove tc filters left behind by an earlier run on ifindex. */
void dp_detach_stale_tc(int ifindex);

int maps_open_pinned(struct lg_maps *m, const char *pin_dir);
void maps_close(struct lg_maps *m);

int maps_set_config(const struct lg_maps *m, const struct lg_config *c);
int maps_get_config(const struct lg_maps *m, struct lg_config *c);
int maps_counters(const struct lg_maps *m, uint64_t out[LG_R_MAX]);
/* Add to a counter only userspace writes, such as LG_R_IMPORT. */
int maps_counter_add(const struct lg_maps *m, uint32_t reason, uint64_t delta);

/* All bindings, DHCP first then static. Caller frees *out. */
int maps_bindings(const struct lg_maps *m, struct lg_binding **out, size_t *n);

/* Make the static map hold exactly want[0..n). */
int maps_sync_static(const struct lg_maps *m, const struct lg_static_key *want, size_t n);

/*
 * Remove leases that expired more than grace_secs ago, pending requests past
 * their TTL, and anything keyed on an ifindex for which alive() is false.
 */
int maps_gc(const struct lg_maps *m, uint64_t grace_secs,
	    bool (*alive)(int ifindex, void *arg), void *arg, struct lg_gc_stats *st);

/* Unpin every map in pin_dir and remove the directory. */
int lg_unpin(const char *pin_dir);

const char *reason_name(unsigned int r);
const char *reason_desc(unsigned int r);
const char *mode_name(unsigned int mode);
const char *ipv6_policy_name(unsigned int p);
const char *attach_mode_name(enum lg_attach_mode m);

#endif
