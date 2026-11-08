// SPDX-License-Identifier: MIT
#include "nl.h"

#include <errno.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NL_BUF 65536

int nl_open(unsigned int groups)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_groups = groups };
	int bufsize = 1 << 20;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | (groups ? SOCK_NONBLOCK : 0),
		    NETLINK_ROUTE);
	if (fd < 0)
		return -errno;
	/* A big receive buffer makes ENOBUFS (and a full resync) rare. */
	if (groups)
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) {
		int err = -errno;

		close(fd);
		return err;
	}
	return fd;
}

static void parse_linkinfo(struct rtattr *info, int len, struct nl_link *l)
{
	for (struct rtattr *a = RTA_DATA(info); RTA_OK(a, len); a = RTA_NEXT(a, len)) {
		if (a->rta_type == IFLA_INFO_KIND) {
			size_t n = RTA_PAYLOAD(a);

			if (n >= sizeof(l->kind))
				n = sizeof(l->kind) - 1;
			memcpy(l->kind, RTA_DATA(a), n);
			l->kind[n] = '\0';
		}
	}
}

static int handle_msg(struct nlmsghdr *h, nl_link_cb cb, void *arg)
{
	struct ifinfomsg *ifi;
	struct nl_link l = {0};
	int len;

	if (h->nlmsg_type != RTM_NEWLINK && h->nlmsg_type != RTM_DELLINK)
		return 0;
	if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi)))
		return 0;
	ifi = NLMSG_DATA(h);
	l.ifindex = ifi->ifi_index;
	len = (int)IFLA_PAYLOAD(h);
	for (struct rtattr *a = IFLA_RTA(ifi); RTA_OK(a, len); a = RTA_NEXT(a, len)) {
		switch (a->rta_type) {
		case IFLA_IFNAME: {
			size_t n = RTA_PAYLOAD(a);

			if (n >= sizeof(l.name))
				n = sizeof(l.name) - 1;
			memcpy(l.name, RTA_DATA(a), n);
			l.name[n] = '\0';
			break;
		}
		case IFLA_MASTER:
			if (RTA_PAYLOAD(a) >= sizeof(int))
				memcpy(&l.master, RTA_DATA(a), sizeof(int));
			break;
		case IFLA_LINKINFO:
			parse_linkinfo(a, (int)RTA_PAYLOAD(a), &l);
			break;
		}
	}
	return cb(&l, h->nlmsg_type == RTM_DELLINK, arg);
}

int nl_dump_links(int fd, nl_link_cb cb, void *arg)
{
	static unsigned int seq;
	struct {
		struct nlmsghdr h;
		struct ifinfomsg ifi;
	} req = {
		.h = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
			.nlmsg_seq = ++seq,
		},
		.ifi = { .ifi_family = AF_UNSPEC },
	};
	static char buf[NL_BUF] __attribute__((aligned(NLMSG_ALIGNTO)));
	int err = 0;

	if (send(fd, &req, req.h.nlmsg_len, 0) < 0)
		return -errno;

	for (;;) {
		ssize_t n = recv(fd, buf, sizeof(buf), 0);
		int len;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		len = (int)n;
		for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, len);
		     h = NLMSG_NEXT(h, len)) {
			if (h->nlmsg_seq != seq)
				continue;
			if (h->nlmsg_type == NLMSG_DONE)
				return err;
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(h);

				if (e->error)
					return e->error;
				continue;
			}
			if (!err)
				err = handle_msg(h, cb, arg);
		}
	}
}

int nl_drain(int fd, nl_link_cb cb, void *arg)
{
	static char buf[NL_BUF] __attribute__((aligned(NLMSG_ALIGNTO)));

	for (;;) {
		ssize_t n = recv(fd, buf, sizeof(buf), 0);
		int len;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -errno;
		}
		len = (int)n;
		for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, len);
		     h = NLMSG_NEXT(h, len))
			handle_msg(h, cb, arg);
	}
}
