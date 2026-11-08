// SPDX-License-Identifier: MIT
#include "leases.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "util.h"

#define INFINITE_LIFETIME 0xffffffffu

static const char *const format_names[] = {
	[LEASES_DNSMASQ] = "dnsmasq",
	[LEASES_LIBVIRT] = "libvirt",
	[LEASES_KEA] = "kea",
	[LEASES_ISC] = "isc",
};

const char *lease_format_name(enum lease_format f)
{
	return (size_t)f < ARRAY_SIZE(format_names) ? format_names[f] : "unknown";
}

/* A parsed record before deduplication: later records for an address win. */
struct raw {
	struct lease_rec r;
	bool active;
	size_t seq;
};

struct rawvec {
	struct raw *v;
	size_t n, cap;
};

static int push(struct rawvec *rv, const struct lease_rec *r, bool active)
{
	if (grow((void **)&rv->v, &rv->cap, rv->n + 1, sizeof(*rv->v)))
		return -ENOMEM;
	rv->v[rv->n] = (struct raw){ .r = *r, .active = active, .seq = rv->n };
	rv->n++;
	return 0;
}

static int cmp_raw(const void *a, const void *b)
{
	const struct raw *x = a, *y = b;

	if (x->r.ip != y->r.ip)
		return x->r.ip < y->r.ip ? -1 : 1;
	return x->seq < y->seq ? -1 : x->seq > y->seq;
}

/* Keep the last record per address, and only if it is active. */
static int finish(struct rawvec *rv, bool dedupe, struct lease_rec **out, size_t *n)
{
	struct lease_rec *res = NULL;
	size_t cap = 0, cnt = 0;

	if (dedupe)
		qsort(rv->v, rv->n, sizeof(*rv->v), cmp_raw);
	for (size_t i = 0; i < rv->n; i++) {
		if (dedupe && i + 1 < rv->n && rv->v[i + 1].r.ip == rv->v[i].r.ip)
			continue;
		if (!rv->v[i].active)
			continue;
		if (grow((void **)&res, &cap, cnt + 1, sizeof(*res))) {
			free(res);
			free(rv->v);
			return -ENOMEM;
		}
		res[cnt++] = rv->v[i].r;
	}
	free(rv->v);
	*out = res;
	*n = cnt;
	return 0;
}

static char *trim(char *s)
{
	char *e;

	while (isspace((unsigned char)*s))
		s++;
	e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = '\0';
	return s;
}

static bool parse_i64(const char *s, int64_t *out)
{
	char *end;
	long long v;

	errno = 0;
	v = strtoll(s, &end, 10);
	if (errno || end == s)
		return false;
	*out = v;
	return true;
}

/*
 * dnsmasq: "EXPIRY MAC IP HOSTNAME CLIENTID" per DHCPv4 lease, EXPIRY in unix
 * seconds or 0 for infinite. DHCPv6 lines (an IAID instead of a MAC) and the
 * "duid" line do not parse as IPv4 leases and are skipped.
 */
static int parse_dnsmasq(FILE *in, struct rawvec *rv)
{
	char *line = NULL;
	size_t cap = 0;
	int err = 0;

	while (getline(&line, &cap, in) > 0) {
		char exp[32], mac[64], ip[64];
		struct lease_rec r = {0};

		if (sscanf(line, "%31s %63s %63s", exp, mac, ip) != 3)
			continue;
		if (!parse_i64(exp, &r.expires) || parse_mac(mac, r.mac) || parse_ipv4(ip, &r.ip))
			continue;
		err = push(rv, &r, true);
		if (err)
			break;
	}
	free(line);
	return err;
}

/* --- libvirt: a JSON array of flat objects ------------------------------ */

struct json {
	const char *p, *end;
};

static void json_ws(struct json *j)
{
	while (j->p < j->end && isspace((unsigned char)*j->p))
		j->p++;
}

static bool json_eat(struct json *j, char c)
{
	json_ws(j);
	if (j->p < j->end && *j->p == c) {
		j->p++;
		return true;
	}
	return false;
}

/* A string into out (truncated to n-1), escapes other than \" and \\ kept raw. */
static bool json_string(struct json *j, char *out, size_t n)
{
	size_t len = 0;

	if (!json_eat(j, '"'))
		return false;
	while (j->p < j->end && *j->p != '"') {
		char c = *j->p++;

		if (c == '\\' && j->p < j->end)
			c = *j->p++;
		if (out && len + 1 < n)
			out[len++] = c;
	}
	if (out)
		out[len] = '\0';
	return json_eat(j, '"');
}

static bool json_skip(struct json *j, int depth);

static bool json_number(struct json *j, int64_t *v)
{
	const char *start;
	char buf[32];
	size_t n;

	json_ws(j);
	start = j->p;
	while (j->p < j->end && (isdigit((unsigned char)*j->p) || strchr("+-.eE", *j->p)))
		j->p++;
	n = (size_t)(j->p - start);
	if (n == 0 || n >= sizeof(buf))
		return false;
	memcpy(buf, start, n);
	buf[n] = '\0';
	return parse_i64(buf, v);
}

static bool json_skip(struct json *j, int depth)
{
	int64_t ignored;

	if (depth > 16)
		return false;
	json_ws(j);
	if (j->p >= j->end)
		return false;
	switch (*j->p) {
	case '"':
		return json_string(j, NULL, 0);
	case '{':
	case '[': {
		char close = *j->p == '{' ? '}' : ']';
		bool obj = *j->p == '{';

		j->p++;
		if (json_eat(j, close))
			return true;
		do {
			if (obj && (!json_string(j, NULL, 0) || !json_eat(j, ':')))
				return false;
			if (!json_skip(j, depth + 1))
				return false;
		} while (json_eat(j, ','));
		return json_eat(j, close);
	}
	case 't':
	case 'f':
	case 'n':
		while (j->p < j->end && isalpha((unsigned char)*j->p))
			j->p++;
		return true;
	}
	return json_number(j, &ignored);
}

static int parse_libvirt(FILE *in, struct rawvec *rv)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	struct json j;
	int err = 0;

	for (;;) {
		size_t got;

		if (grow((void **)&buf, &cap, len + 4096, 1))
			return -ENOMEM;
		got = fread(buf + len, 1, cap - len, in);
		len += got;
		if (got == 0)
			break;
	}
	j.p = buf;
	j.end = buf + len;

	if (!json_eat(&j, '[')) {
		free(buf);
		return len ? -EINVAL : 0;   /* an empty file has no leases */
	}
	if (json_eat(&j, ']')) {
		free(buf);
		return 0;
	}
	do {
		char ip[64] = "", mac[64] = "";
		int64_t expiry = -1;
		struct lease_rec r = {0};

		if (!json_eat(&j, '{')) {
			err = -EINVAL;
			break;
		}
		if (!json_eat(&j, '}')) {
			do {
				char key[32];

				if (!json_string(&j, key, sizeof(key)) || !json_eat(&j, ':')) {
					err = -EINVAL;
					break;
				}
				if (!strcmp(key, "ip-address")) {
					if (!json_string(&j, ip, sizeof(ip)))
						err = -EINVAL;
				} else if (!strcmp(key, "mac-address")) {
					if (!json_string(&j, mac, sizeof(mac)))
						err = -EINVAL;
				} else if (!strcmp(key, "expiry-time")) {
					if (!json_number(&j, &expiry))
						err = -EINVAL;
				} else if (!json_skip(&j, 0)) {
					err = -EINVAL;
				}
			} while (!err && json_eat(&j, ','));
			if (!err && !json_eat(&j, '}'))
				err = -EINVAL;
		}
		if (err)
			break;
		/* DHCPv6 entries have an iaid and an IPv6 address: skipped here. */
		if (expiry < 0 || parse_mac(mac, r.mac) || parse_ipv4(ip, &r.ip))
			continue;
		r.expires = expiry;
		err = push(rv, &r, true);
	} while (!err && json_eat(&j, ','));
	if (!err && !json_eat(&j, ']'))
		err = -EINVAL;
	free(buf);
	return err;
}

/* --- Kea memfile CSV ------------------------------------------------------ */

/* Split a CSV line in place. Kea escapes commas inside values. */
static size_t split_csv(char *line, char **fields, size_t max)
{
	size_t n = 0;
	char *p = line;

	while (n < max) {
		fields[n++] = p;
		p = strchr(p, ',');
		if (!p)
			break;
		*p++ = '\0';
	}
	for (size_t i = 0; i < n; i++)
		fields[i] = trim(fields[i]);
	return n;
}

/*
 * The file is a log: each change to a lease appends a record, and the last
 * record for an address is current. A record is active in state 0 with a
 * non-zero valid lifetime (deleted leases are written with lifetime 0).
 */
static int parse_kea(FILE *in, struct rawvec *rv)
{
	enum { COL_ADDRESS, COL_HWADDR, COL_LIFETIME, COL_EXPIRE, COL_STATE, NCOLS };
	static const char *const names[NCOLS] = {
		"address", "hwaddr", "valid_lifetime", "expire", "state",
	};
	int col[NCOLS] = { -1, -1, -1, -1, -1 };
	char *line = NULL, *fields[64];
	size_t cap = 0;
	bool header = false;
	int err = 0;

	while (getline(&line, &cap, in) > 0) {
		size_t n = split_csv(line, fields, ARRAY_SIZE(fields));
		struct lease_rec r = {0};
		int64_t lifetime, state = 0;

		if (n == 1 && fields[0][0] == '\0')
			continue;
		if (!header) {
			for (size_t i = 0; i < n; i++)
				for (int c = 0; c < NCOLS; c++)
					if (!strcmp(fields[i], names[c]))
						col[c] = (int)i;
			if (col[COL_ADDRESS] < 0 || col[COL_HWADDR] < 0 || col[COL_LIFETIME] < 0 ||
			    col[COL_EXPIRE] < 0) {
				err = -EINVAL;
				break;
			}
			header = true;
			continue;
		}
		if ((int)n <= col[COL_ADDRESS] || (int)n <= col[COL_HWADDR] ||
		    (int)n <= col[COL_LIFETIME] || (int)n <= col[COL_EXPIRE])
			continue;
		if (parse_ipv4(fields[col[COL_ADDRESS]], &r.ip) ||
		    !parse_i64(fields[col[COL_LIFETIME]], &lifetime) ||
		    !parse_i64(fields[col[COL_EXPIRE]], &r.expires))
			continue;
		if (col[COL_STATE] >= 0 && (int)n > col[COL_STATE])
			parse_i64(fields[col[COL_STATE]], &state);
		/* A record without a usable hardware address still supersedes older ones. */
		bool has_mac = parse_mac(fields[col[COL_HWADDR]], r.mac) == 0;

		if (lifetime == INFINITE_LIFETIME)
			r.expires = 0;
		err = push(rv, &r, has_mac && state == 0 && lifetime > 0);
		if (err)
			break;
	}
	free(line);
	return err;
}

/* --- ISC dhcpd.leases ----------------------------------------------------- */

/* "never", "epoch N" or "W YYYY/MM/DD HH:MM:SS" (UTC). */
static bool parse_isc_time(const char *s, int64_t *out)
{
	struct tm tm = {0};
	int wday;

	if (!strncmp(s, "never", 5)) {
		*out = 0;
		return true;
	}
	if (!strncmp(s, "epoch ", 6))
		return parse_i64(s + 6, out);
	if (sscanf(s, "%d %d/%d/%d %d:%d:%d", &wday, &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
		   &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 7)
		return false;
	tm.tm_year -= 1900;
	tm.tm_mon -= 1;
	*out = (int64_t)timegm(&tm);
	return true;
}

static int parse_isc(FILE *in, struct rawvec *rv)
{
	char *line = NULL;
	size_t cap = 0;
	bool in_lease = false, active = false, has_mac = false;
	struct lease_rec r = {0};
	int err = 0;

	while (!err && getline(&line, &cap, in) > 0) {
		char *s = trim(line);

		if (!in_lease) {
			char ip[64];

			if (sscanf(s, "lease %63[0-9.] {", ip) == 1 && parse_ipv4(ip, &r.ip) == 0) {
				in_lease = true;
				active = has_mac = false;
				r.expires = 0;
			}
			continue;
		}
		if (s[0] == '}') {
			if (has_mac)
				err = push(rv, &r, active);
			in_lease = false;
		} else if (!strncmp(s, "ends ", 5)) {
			if (!parse_isc_time(s + 5, &r.expires))
				r.expires = 0;
		} else if (!strncmp(s, "binding state ", 14)) {
			active = !strncmp(s + 14, "active;", 7);
		} else if (!strncmp(s, "hardware ethernet ", 18)) {
			char mac[32];

			has_mac = sscanf(s + 18, "%31[0-9a-fA-F:]", mac) == 1 && parse_mac(mac, r.mac) == 0;
		}
	}
	free(line);
	return err;
}

int leases_parse(enum lease_format f, FILE *in, struct lease_rec **out, size_t *n)
{
	struct rawvec rv = {0};
	int err;

	switch (f) {
	case LEASES_DNSMASQ:
		err = parse_dnsmasq(in, &rv);
		break;
	case LEASES_LIBVIRT:
		err = parse_libvirt(in, &rv);
		break;
	case LEASES_KEA:
		err = parse_kea(in, &rv);
		break;
	case LEASES_ISC:
		err = parse_isc(in, &rv);
		break;
	default:
		err = -EINVAL;
	}
	if (err) {
		free(rv.v);
		return err;
	}
	/* dnsmasq and libvirt hold current state only; the others are logs. */
	return finish(&rv, f == LEASES_KEA || f == LEASES_ISC, out, n);
}

int lease_source_init(struct lease_source *s, const char *spec)
{
	const char *colon = strchr(spec, ':');

	memset(s, 0, sizeof(*s));
	if (!colon || colon == spec || !colon[1])
		return -EINVAL;
	for (size_t i = 0; i < ARRAY_SIZE(format_names); i++) {
		if (strlen(format_names[i]) == (size_t)(colon - spec) &&
		    !strncmp(spec, format_names[i], (size_t)(colon - spec))) {
			s->format = (enum lease_format)i;
			if (strlen(colon + 1) >= sizeof(s->path))
				return -ENAMETOOLONG;
			strcpy(s->path, colon + 1);
			return 0;
		}
	}
	return -EINVAL;
}

void lease_source_free(struct lease_source *s)
{
	free(s->recs);
	s->recs = NULL;
	s->n = 0;
	s->loaded = false;
}

int lease_source_refresh(struct lease_source *s)
{
	struct lease_rec *recs = NULL;
	struct stat st;
	size_t n = 0;
	FILE *f;
	int err;

	if (stat(s->path, &st)) {
		err = -errno;
		if (err == -ENOENT) {
			if (!s->missing_reported)
				log_warn("msg=\"lease file not found, will keep looking\" format=%s path=%s",
					 lease_format_name(s->format), s->path);
			s->missing_reported = true;
			if (s->loaded) {
				lease_source_free(s);
				return 1;
			}
			return 0;
		}
		return err;
	}
	if (s->loaded && st.st_dev == s->dev && st.st_ino == s->ino && st.st_size == s->size &&
	    st.st_mtim.tv_sec == s->mtime.tv_sec && st.st_mtim.tv_nsec == s->mtime.tv_nsec)
		return 0;

	f = fopen(s->path, "re");
	if (!f)
		return -errno;
	err = leases_parse(s->format, f, &recs, &n);
	fclose(f);
	if (err) {
		log_warn("msg=\"cannot parse lease file, keeping the previous contents\" format=%s "
			 "path=%s error=\"%s\"", lease_format_name(s->format), s->path, strerror(-err));
		return err;
	}
	free(s->recs);
	s->recs = recs;
	s->n = n;
	s->loaded = true;
	s->missing_reported = false;
	s->dev = st.st_dev;
	s->ino = st.st_ino;
	s->size = st.st_size;
	s->mtime = st.st_mtim;
	log_debug("msg=\"read lease file\" format=%s path=%s leases=%zu",
		  lease_format_name(s->format), s->path, n);
	return 1;
}

const struct lease_rec *lease_find(const struct lease_source *srcs, size_t nsrcs,
				   const uint8_t mac[6], uint32_t ip, time_t now,
				   const struct lease_source **from)
{
	for (size_t i = 0; i < nsrcs; i++) {
		for (size_t k = 0; k < srcs[i].n; k++) {
			const struct lease_rec *r = &srcs[i].recs[k];

			if (r->ip == ip && !memcmp(r->mac, mac, 6) && (r->expires == 0 || r->expires > now)) {
				if (from)
					*from = &srcs[i];
				return r;
			}
		}
	}
	return NULL;
}
