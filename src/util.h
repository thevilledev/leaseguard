/* SPDX-License-Identifier: MIT */
#ifndef LG_UTIL_H
#define LG_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

enum lg_log_level {
	LGL_ERROR,
	LGL_WARN,
	LGL_INFO,
	LGL_DEBUG,
	LGL_TRACE,  /* libbpf's own debug output */
};

extern int lg_log_level;

void lg_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#define log_error(...) lg_log(LGL_ERROR, __VA_ARGS__)
#define log_warn(...)  lg_log(LGL_WARN, __VA_ARGS__)
#define log_info(...)  lg_log(LGL_INFO, __VA_ARGS__)
#define log_debug(...) lg_log(LGL_DEBUG, __VA_ARGS__)

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* CLOCK_BOOTTIME in nanoseconds, the clock bpf_ktime_get_boot_ns() reads. */
uint64_t boot_ns(void);

/* Wall-clock time for a CLOCK_BOOTTIME timestamp. */
time_t boot_to_wall(uint64_t ns);

int parse_mac(const char *s, uint8_t mac[6]);
/* Dotted quad to network byte order. */
int parse_ipv4(const char *s, uint32_t *be);
int parse_u32(const char *s, uint32_t *out);

/* Buffers: MAC 18 bytes, IPv4 16 bytes. */
void fmt_mac(const uint8_t mac[6], char *out);
void fmt_ipv4(uint32_t be, char *out);
/* Compact duration such as "1h2m3s". */
void fmt_duration(uint64_t secs, char *out, size_t n);

/* Grow *arr to hold at least want elements of size sz. */
int grow(void **arr, size_t *cap, size_t want, size_t sz);

#endif
