/* SPDX-License-Identifier: MIT */
/* Just enough rtnetlink to list links and follow link changes. */
#ifndef LG_NL_H
#define LG_NL_H

#include <net/if.h>
#include <stdbool.h>

struct nl_link {
	int ifindex;
	int master;             /* ifindex of the master device, 0 if none */
	char name[IF_NAMESIZE];
	char kind[32];          /* IFLA_INFO_KIND, e.g. "bridge"; empty if absent */
};

typedef int (*nl_link_cb)(const struct nl_link *l, bool deleted, void *arg);

/* Netlink route socket; groups is RTMGRP_LINK to receive link events, or 0. */
int nl_open(unsigned int groups);

/* Request a link dump and call cb for each link. */
int nl_dump_links(int fd, nl_link_cb cb, void *arg);

/*
 * Read whatever notifications are queued on a non-blocking socket.
 * Returns -ENOBUFS when the kernel dropped notifications (resync needed).
 */
int nl_drain(int fd, nl_link_cb cb, void *arg);

#endif
