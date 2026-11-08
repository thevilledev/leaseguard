// SPDX-License-Identifier: MIT
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int lg_log_level = LGL_INFO;

static const char *const level_names[] = {
	[LGL_ERROR] = "error",
	[LGL_WARN] = "warn",
	[LGL_INFO] = "info",
	[LGL_DEBUG] = "debug",
	[LGL_TRACE] = "trace",
};

void lg_log(int level, const char *fmt, ...)
{
	static int timestamps = -1;
	char ts[32] = "";
	va_list ap;

	if (level > lg_log_level)
		return;
	/* The journal stamps lines itself. */
	if (timestamps < 0)
		timestamps = getenv("JOURNAL_STREAM") == NULL;
	if (timestamps) {
		struct timespec now;
		struct tm tm;

		clock_gettime(CLOCK_REALTIME, &now);
		gmtime_r(&now.tv_sec, &tm);
		strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ ", &tm);
	}

	flockfile(stderr);
	fprintf(stderr, "%slevel=%s ", ts, level_names[level]);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	funlockfile(stderr);
}

uint64_t boot_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_BOOTTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

time_t boot_to_wall(uint64_t ns)
{
	int64_t delta = (int64_t)(ns / 1000000000ULL) - (int64_t)(boot_ns() / 1000000000ULL);

	return time(NULL) + delta;
}

int parse_mac(const char *s, uint8_t mac[6])
{
	unsigned int b[6];
	char tail;

	if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c", &b[0], &b[1], &b[2], &b[3], &b[4],
		   &b[5], &tail) != 6 &&
	    sscanf(s, "%2x-%2x-%2x-%2x-%2x-%2x%c", &b[0], &b[1], &b[2], &b[3], &b[4],
		   &b[5], &tail) != 6)
		return -EINVAL;
	for (int i = 0; i < 6; i++)
		mac[i] = (uint8_t)b[i];
	return 0;
}

int parse_ipv4(const char *s, uint32_t *be)
{
	struct in_addr a;

	if (inet_pton(AF_INET, s, &a) != 1)
		return -EINVAL;
	*be = a.s_addr;
	return 0;
}

int parse_u32(const char *s, uint32_t *out)
{
	char *end;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno || end == s || *end || v > UINT32_MAX)
		return -EINVAL;
	*out = (uint32_t)v;
	return 0;
}

void fmt_mac(const uint8_t mac[6], char *out)
{
	snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void fmt_ipv4(uint32_t be, char *out)
{
	struct in_addr a = { .s_addr = be };

	inet_ntop(AF_INET, &a, out, 16);
}

void fmt_duration(uint64_t secs, char *out, size_t n)
{
	uint64_t d = secs / 86400, h = secs / 3600 % 24, m = secs / 60 % 60, s = secs % 60;

	if (d)
		snprintf(out, n, "%llud%lluh", (unsigned long long)d, (unsigned long long)h);
	else if (h)
		snprintf(out, n, "%lluh%llum", (unsigned long long)h, (unsigned long long)m);
	else if (m)
		snprintf(out, n, "%llum%llus", (unsigned long long)m, (unsigned long long)s);
	else
		snprintf(out, n, "%llus", (unsigned long long)s);
}

int grow(void **arr, size_t *cap, size_t want, size_t sz)
{
	size_t ncap = *cap ? *cap : 16;
	void *p;

	if (want <= *cap)
		return 0;
	while (ncap < want)
		ncap *= 2;
	p = realloc(*arr, ncap * sz);
	if (!p)
		return -ENOMEM;
	*arr = p;
	*cap = ncap;
	return 0;
}
