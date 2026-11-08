// SPDX-License-Identifier: MIT
#include "daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "import.h"
#include "leases.h"
#include "nl.h"
#include "statics.h"
#include "util.h"

/* Expired leases linger this long before collection, for `bindings` output. */
#define GC_GRACE_SECS 300
/* Lease files and the bindings snapshot are re-read at most this often. */
#define IMPORT_REFRESH_NS 1000000000ULL

struct port {
	int ifindex;
	char name[IF_NAMESIZE];
	struct lg_attachment att;
	bool keep;
};

struct daemon {
	const struct run_opts *o;
	struct lg_dp dp;
	enum lg_attach_mode mode;   /* AUTO until the first attach settles it */
	int bridge_ifindex;

	struct port *ports;
	size_t nports, ports_cap;

	struct nl_link *links;      /* latest link dump */
	size_t nlinks, links_cap;

	struct static_entry *statics;
	size_t nstatics;

	struct lease_source *sources;   /* lease files to import from */
	size_t nsources;
	uint64_t sources_ns;            /* CLOCK_BOOTTIME of the last refresh */
	struct lg_binding *snap;        /* bindings, for import conflict checks */
	size_t nsnap;
	uint64_t snap_ns;

	int nl_dump, nl_mon, tfd, sfd, efd, lock_fd;
	struct ring_buffer *rb;
};

int lg_lock(const char *pin_dir)
{
	int fd = open(pin_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (fd < 0)
		return -errno;
	if (flock(fd, LOCK_EX | LOCK_NB)) {
		int err = errno == EWOULDBLOCK ? -EBUSY : -errno;

		close(fd);
		return err;
	}
	return fd;
}

static bool is_trusted(const struct daemon *d, const char *name)
{
	for (size_t i = 0; i < d->o->ntrusted; i++)
		if (fnmatch(d->o->trusted[i], name, 0) == 0)
			return true;
	return false;
}

static struct port *find_port(struct daemon *d, int ifindex)
{
	for (size_t i = 0; i < d->nports; i++)
		if (d->ports[i].ifindex == ifindex)
			return &d->ports[i];
	return NULL;
}

static const struct nl_link *find_link_by_name(const struct daemon *d, const char *name)
{
	for (size_t i = 0; i < d->nlinks; i++)
		if (strcmp(d->links[i].name, name) == 0)
			return &d->links[i];
	return NULL;
}

static void port_name(struct daemon *d, int ifindex, char *out, size_t n)
{
	struct port *p = find_port(d, ifindex);
	char name[IF_NAMESIZE];

	if (p)
		snprintf(out, n, "%s", p->name);
	else if (if_indextoname((unsigned int)ifindex, name))
		snprintf(out, n, "%s", name);
	else
		snprintf(out, n, "if%d", ifindex);
}

static int collect_link(const struct nl_link *l, bool deleted, void *arg)
{
	struct daemon *d = arg;

	if (deleted)
		return 0;
	if (grow((void **)&d->links, &d->links_cap, d->nlinks + 1, sizeof(*d->links)))
		return -ENOMEM;
	d->links[d->nlinks++] = *l;
	return 0;
}

static bool link_alive(int ifindex, void *arg)
{
	struct daemon *d = arg;

	for (size_t i = 0; i < d->nlinks; i++)
		if (d->links[i].ifindex == ifindex)
			return true;
	return false;
}

static void sync_statics(struct daemon *d)
{
	struct lg_static_key *want;
	size_t n = 0;
	int err;

	want = calloc(d->nstatics + 1, sizeof(*want));
	if (!want)
		return;
	for (size_t i = 0; i < d->nstatics; i++) {
		const struct static_entry *e = &d->statics[i];
		const struct nl_link *l = find_link_by_name(d, e->port);

		/* Ports come and go; the binding applies while the port exists. */
		if (!l || l->master != d->bridge_ifindex)
			continue;
		want[n].ifindex = (__u32)l->ifindex;
		want[n].vlan = e->vlan;
		want[n].ip = e->ip;
		memcpy(want[n].mac, e->mac, LG_MAC_LEN);
		n++;
	}
	err = maps_sync_static(&d->dp.maps, want, n);
	if (err)
		log_error("msg=\"cannot update static bindings\" error=\"%s\"", strerror(-err));
	free(want);
}

static void attach_port(struct daemon *d, const struct nl_link *l)
{
	struct port p = { .ifindex = l->ifindex, .keep = true };
	int err;

	snprintf(p.name, sizeof(p.name), "%s", l->name);
	err = dp_attach(&d->dp, l->ifindex, d->mode, &p.att);
	if (err) {
		log_error("msg=\"cannot attach\" port=%s ifindex=%d error=\"%s\"", l->name,
			  l->ifindex, strerror(-err));
		return;
	}
	if (d->mode == LG_ATTACH_AUTO)
		d->mode = p.att.mode;
	if (grow((void **)&d->ports, &d->ports_cap, d->nports + 1, sizeof(*d->ports))) {
		dp_detach(&p.att);
		return;
	}
	d->ports[d->nports++] = p;
	log_info("msg=attached port=%s ifindex=%d via=%s", p.name, p.ifindex,
		 attach_mode_name(p.att.mode));
}

static void detach_port(struct daemon *d, size_t i, const char *why)
{
	log_info("msg=detached port=%s ifindex=%d reason=\"%s\"", d->ports[i].name,
		 d->ports[i].ifindex, why);
	dp_detach(&d->ports[i].att);
	d->ports[i] = d->ports[--d->nports];
}

/* Bring attachments in line with the bridge's current ports. */
static int reconcile(struct daemon *d)
{
	const struct nl_link *br;
	int err;

	d->nlinks = 0;
	err = nl_dump_links(d->nl_dump, collect_link, d);
	if (err) {
		log_error("msg=\"cannot list links\" error=\"%s\"", strerror(-err));
		return err;
	}

	br = find_link_by_name(d, d->o->bridge);
	if (!br || strcmp(br->kind, "bridge") != 0) {
		if (d->bridge_ifindex)
			log_error("msg=\"bridge is gone\" bridge=%s", d->o->bridge);
		d->bridge_ifindex = 0;
	} else {
		d->bridge_ifindex = br->ifindex;
	}

	for (size_t i = 0; i < d->nports; i++)
		d->ports[i].keep = false;

	for (size_t i = 0; d->bridge_ifindex && i < d->nlinks; i++) {
		const struct nl_link *l = &d->links[i];
		struct port *p;

		if (l->master != d->bridge_ifindex || is_trusted(d, l->name))
			continue;
		p = find_port(d, l->ifindex);
		if (p) {
			p->keep = true;
			if (strcmp(p->name, l->name)) {
				log_info("msg=renamed port=%s old=%s ifindex=%d", l->name, p->name, l->ifindex);
				snprintf(p->name, sizeof(p->name), "%s", l->name);
			}
			continue;
		}
		attach_port(d, l);
	}

	for (size_t i = d->nports; i-- > 0;) {
		if (d->ports[i].keep)
			continue;
		detach_port(d, i, link_alive(d->ports[i].ifindex, d) ? "left the bridge" : "removed");
	}

	sync_statics(d);
	return 0;
}

static void collect_garbage(struct daemon *d)
{
	struct lg_gc_stats st;
	int err;

	err = maps_gc(&d->dp.maps, GC_GRACE_SECS, link_alive, d, &st);
	if (err) {
		log_error("msg=\"garbage collection failed\" error=\"%s\"", strerror(-err));
		return;
	}
	if (st.leases || st.pending)
		log_debug("msg=gc leases=%u pending=%u", st.leases, st.pending);
}

static int load_statics(struct daemon *d)
{
	struct static_entry *s = NULL;
	size_t n = 0;
	int err;

	if (!d->o->static_file)
		return 0;
	err = statics_load(d->o->static_file, &s, &n);
	if (err)
		return err;
	free(d->statics);
	d->statics = s;
	d->nstatics = n;
	log_info("msg=\"loaded static bindings\" path=%s count=%zu", d->o->static_file, n);
	return 0;
}

static void refresh_sources(struct daemon *d, bool force)
{
	uint64_t now = boot_ns();

	if (!force && now - d->sources_ns < IMPORT_REFRESH_NS)
		return;
	d->sources_ns = now;
	for (size_t i = 0; i < d->nsources; i++)
		lease_source_refresh(&d->sources[i]);
}

/* Returns 1 if the snapshot was re-read, 0 if the cached one is recent enough. */
static int refresh_snapshot(struct daemon *d, bool force)
{
	struct lg_binding *b = NULL;
	uint64_t now = boot_ns();
	size_t n = 0;
	int err;

	if (!force && d->snap && now - d->snap_ns < IMPORT_REFRESH_NS)
		return 0;
	err = maps_bindings(&d->dp.maps, &b, &n);
	if (err)
		return err;
	free(d->snap);
	d->snap = b;
	d->nsnap = n;
	d->snap_ns = now;
	return 1;
}

/*
 * A violation came in: if the server's lease file says this MAC holds this
 * address, bind it. The event's port and VLAN are what the datapath keys on.
 */
static void try_import(struct daemon *d, const struct lg_event *e, const char *port)
{
	const struct lease_source *src = NULL;
	const struct lease_rec *lease;
	struct lg_key key = { .ifindex = e->ifindex, .vlan = e->vlan };
	struct lg_lease cur, val;
	enum import_action act;
	char mac[18], ip[16], exp[32];
	time_t now = time(NULL);
	uint64_t nowb;
	bool have_cur, conflict;
	int fresh;

	if (!d->nsources || !e->ip || !import_candidate(e->reason) || !find_port(d, (int)e->ifindex))
		return;
	refresh_sources(d, false);
	lease = lease_find(d->sources, d->nsources, e->mac, e->ip, now, &src);
	if (!lease)
		return;
	fresh = refresh_snapshot(d, false);
	if (fresh < 0)
		return;

	memcpy(key.mac, e->mac, LG_MAC_LEN);
	nowb = boot_ns();
	have_cur = bpf_map_lookup_elem(d->dp.maps.leases, &key, &cur) == 0;
	conflict = import_conflict(d->snap, d->nsnap, &key, e->ip, nowb);
	act = import_decide(lease, have_cur ? &cur : NULL, conflict, nowb);
	/*
	 * Before writing, check against current bindings: the datapath may have
	 * bound this address to another port since the cached snapshot.
	 */
	if ((act == IMPORT_INSERT || act == IMPORT_REFRESH) && !fresh) {
		if (refresh_snapshot(d, true) < 0)
			return;
		conflict = import_conflict(d->snap, d->nsnap, &key, e->ip, nowb);
		act = import_decide(lease, have_cur ? &cur : NULL, conflict, nowb);
	}

	fmt_mac(e->mac, mac);
	fmt_ipv4(e->ip, ip);
	if (act != IMPORT_INSERT && act != IMPORT_REFRESH) {
		log_debug("msg=\"no import\" port=%s vlan=%u mac=%s ip=%s reason=%s", port, e->vlan,
			  mac, ip, import_action_name(act));
		return;
	}

	import_value(lease, now, nowb, &val);
	if (bpf_map_update_elem(d->dp.maps.leases, &key, &val,
				act == IMPORT_INSERT ? BPF_NOEXIST : BPF_EXIST)) {
		/* The datapath bound it meanwhile, or GC removed it: either is fine. */
		log_debug("msg=\"import raced\" port=%s mac=%s ip=%s error=\"%s\"", port, mac, ip,
			  strerror(errno));
		return;
	}
	maps_counter_add(&d->dp.maps, LG_R_IMPORT, 1);
	d->snap_ns = 0;   /* the snapshot no longer holds this binding */

	if (lease->expires)
		fmt_duration((uint64_t)(lease->expires - now), exp, sizeof(exp));
	else
		snprintf(exp, sizeof(exp), "never");
	log_info("msg=import port=%s vlan=%u mac=%s ip=%s expires=%s%s source=%s:%s", port,
		 e->vlan, mac, ip, lease->expires ? "in " : "", exp, lease_format_name(src->format),
		 src->path);
}

static int on_event(void *ctx, void *data, size_t size)
{
	struct daemon *d = ctx;
	const struct lg_event *e = data;
	char port[IF_NAMESIZE + 8], mac[18], ip[16];

	if (size < sizeof(*e))
		return 0;
	port_name(d, (int)e->ifindex, port, sizeof(port));
	fmt_mac(e->mac, mac);
	fmt_ipv4(e->ip, ip);

	switch (e->kind) {
	case LG_EV_BIND:
		log_info("msg=bind port=%s vlan=%u mac=%s ip=%s lease=%us", port, e->vlan, mac, ip,
			 e->lease_secs);
		break;
	case LG_EV_UNBIND:
		log_info("msg=unbind port=%s vlan=%u mac=%s ip=%s reason=%s", port, e->vlan, mac, ip,
			 reason_name(e->reason));
		break;
	case LG_EV_DROP:
	case LG_EV_WOULD_DROP:
		log_warn("msg=%s reason=%s port=%s vlan=%u mac=%s ip=%s",
			 e->kind == LG_EV_DROP ? "drop" : "\"would drop\"", reason_name(e->reason),
			 port, e->vlan, mac, e->ip ? ip : "-");
		try_import(d, e, port);
		break;
	}
	return 0;
}

static int note_link_change(const struct nl_link *l, bool deleted, void *arg)
{
	(void)l;
	(void)deleted;
	*(bool *)arg = true;
	return 0;
}

static int setup(struct daemon *d)
{
	const struct run_opts *o = d->o;
	struct lg_config cfg = {
		.mode = o->mode,
		.ipv6_policy = o->ipv6,
		.flags = o->strict_ethertypes ? LG_F_STRICT_ETHERTYPE : 0,
		.event_rate = o->event_rate,
	};
	struct itimerspec its = {
		.it_interval = { .tv_sec = o->interval_secs },
		.it_value = { .tv_sec = o->interval_secs },
	};
	struct epoll_event ev = { .events = EPOLLIN };
	sigset_t mask;
	int err;

	err = lg_ensure_bpffs();
	if (err)
		return err;
	err = dp_load(&d->dp, o->pin_dir);
	if (err)
		return err;
	d->lock_fd = lg_lock(o->pin_dir);
	if (d->lock_fd < 0) {
		if (d->lock_fd == -EBUSY)
			log_error("msg=\"another leaseguard is running on these maps\" pin_dir=%s", o->pin_dir);
		else
			log_error("msg=\"cannot lock pin directory\" pin_dir=%s error=\"%s\"", o->pin_dir,
				  strerror(-d->lock_fd));
		return d->lock_fd;
	}
	err = maps_set_config(&d->dp.maps, &cfg);
	if (err) {
		log_error("msg=\"cannot write config\" error=\"%s\"", strerror(-err));
		return err;
	}
	err = load_statics(d);
	if (err)
		return err;

	if (o->nlease_specs) {
		d->sources = calloc(o->nlease_specs, sizeof(*d->sources));
		if (!d->sources)
			return -ENOMEM;
		for (size_t i = 0; i < o->nlease_specs; i++, d->nsources++) {
			err = lease_source_init(&d->sources[i], o->lease_specs[i]);
			if (err) {
				log_error("msg=\"bad --leases, want FORMAT:PATH with FORMAT dnsmasq, libvirt, "
					  "kea or isc\" value=\"%s\"", o->lease_specs[i]);
				return err;
			}
		}
		refresh_sources(d, true);
		for (size_t i = 0; i < d->nsources; i++)
			log_info("msg=\"importing leases\" format=%s path=%s leases=%zu",
				 lease_format_name(d->sources[i].format), d->sources[i].path,
				 d->sources[i].n);
	}

	/* Subscribe before the first dump so no change slips between them. */
	d->nl_mon = nl_open(RTMGRP_LINK);
	d->nl_dump = nl_open(0);
	if (d->nl_mon < 0 || d->nl_dump < 0) {
		err = d->nl_mon < 0 ? d->nl_mon : d->nl_dump;
		log_error("msg=\"cannot open netlink\" error=\"%s\"", strerror(-err));
		return err;
	}

	err = reconcile(d);
	if (err)
		return err;
	if (!d->bridge_ifindex) {
		log_error("msg=\"no such bridge\" bridge=%s", o->bridge);
		return -ENODEV;
	}

	d->rb = ring_buffer__new(d->dp.events_fd, on_event, d, NULL);
	if (!d->rb) {
		err = -errno;
		log_error("msg=\"cannot open event ring buffer\" error=\"%s\"", strerror(-err));
		return err;
	}

	d->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (d->tfd < 0 || timerfd_settime(d->tfd, 0, &its, NULL))
		return -errno;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGHUP);
	if (sigprocmask(SIG_BLOCK, &mask, NULL))
		return -errno;
	d->sfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
	if (d->sfd < 0)
		return -errno;

	d->efd = epoll_create1(EPOLL_CLOEXEC);
	if (d->efd < 0)
		return -errno;
	ev.data.fd = d->nl_mon;
	if (epoll_ctl(d->efd, EPOLL_CTL_ADD, d->nl_mon, &ev))
		return -errno;
	ev.data.fd = ring_buffer__epoll_fd(d->rb);
	if (epoll_ctl(d->efd, EPOLL_CTL_ADD, ev.data.fd, &ev))
		return -errno;
	ev.data.fd = d->tfd;
	if (epoll_ctl(d->efd, EPOLL_CTL_ADD, d->tfd, &ev))
		return -errno;
	ev.data.fd = d->sfd;
	if (epoll_ctl(d->efd, EPOLL_CTL_ADD, d->sfd, &ev))
		return -errno;
	return 0;
}

static void teardown(struct daemon *d)
{
	size_t n = d->nports;

	while (d->nports)
		dp_detach(&d->ports[--d->nports].att);
	if (n)
		log_info("msg=\"detached from all ports, protection is off until leaseguard runs again\" ports=%zu", n);
	ring_buffer__free(d->rb);
	dp_unload(&d->dp);
	{
		int *fds[] = { &d->nl_dump, &d->nl_mon, &d->tfd, &d->sfd, &d->efd, &d->lock_fd };

		for (size_t i = 0; i < ARRAY_SIZE(fds); i++)
			if (*fds[i] >= 0)
				close(*fds[i]);
	}
	free(d->ports);
	free(d->links);
	free(d->statics);
	for (size_t i = 0; i < d->nsources; i++)
		lease_source_free(&d->sources[i]);
	free(d->sources);
	free(d->snap);
}

int daemon_run(const struct run_opts *o)
{
	struct daemon d = {
		.o = o,
		.mode = o->attach,
		.nl_dump = -1, .nl_mon = -1, .tfd = -1, .sfd = -1, .efd = -1, .lock_fd = -1,
	};
	bool running = true;
	int err;

	if (o->ntrusted == 0)
		log_warn("msg=\"no trusted ports: every port of the bridge is checked, including any "
			 "uplink, so only a DHCP server on the host itself can hand out leases\" bridge=%s",
			 o->bridge);

	err = setup(&d);
	if (err) {
		teardown(&d);
		return err;
	}
	log_info("msg=started bridge=%s mode=%s ipv6=%s attach=%s ports=%zu pin_dir=%s",
		 o->bridge, mode_name(o->mode), ipv6_policy_name(o->ipv6),
		 attach_mode_name(d.mode), d.nports, o->pin_dir);
	if (o->mode == LG_MODE_MONITOR)
		log_info("msg=\"monitor mode: violations are logged, nothing is dropped; "
			 "`leaseguard mode enforce` switches without a restart\"");

	while (running) {
		struct epoll_event evs[8];
		int n = epoll_wait(d.efd, evs, ARRAY_SIZE(evs), -1);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			err = -errno;
			log_error("msg=\"epoll failed\" error=\"%s\"", strerror(-err));
			break;
		}
		for (int i = 0; i < n; i++) {
			int fd = evs[i].data.fd;

			if (fd == d.nl_mon) {
				bool changed = false;
				int r = nl_drain(d.nl_mon, note_link_change, &changed);

				if (r == -ENOBUFS)
					log_warn("msg=\"netlink overrun, resyncing\"");
				if (changed || r == -ENOBUFS)
					reconcile(&d);
			} else if (fd == d.tfd) {
				uint64_t ticks;

				if (read(d.tfd, &ticks, sizeof(ticks)) < 0 && errno != EAGAIN)
					log_warn("msg=\"timer read failed\" error=\"%s\"", strerror(errno));
				reconcile(&d);
				collect_garbage(&d);
			} else if (fd == d.sfd) {
				struct signalfd_siginfo si;

				while (read(d.sfd, &si, sizeof(si)) == sizeof(si)) {
					if (si.ssi_signo == SIGHUP) {
						log_info("msg=\"reloading static bindings\"");
						if (load_statics(&d) == 0)
							reconcile(&d);
					} else {
						log_info("msg=\"stopping\" signal=%s", strsignal((int)si.ssi_signo));
						running = false;
					}
				}
			} else {
				ring_buffer__consume(d.rb);
			}
		}
	}

	ring_buffer__consume(d.rb);
	teardown(&d);
	return err;
}
