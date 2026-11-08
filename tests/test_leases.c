// SPDX-License-Identifier: MIT
/* Lease file parsers and import decisions. No privileges needed. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "import.h"
#include "leases.h"
#include "util.h"

static int failures, checks;
static const char *current;

static void fail(int line, const char *fmt, ...)
{
	va_list ap;

	failures++;
	fprintf(stderr, "FAIL %s (line %d): ", current, line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

#define CHECK(cond, ...) do { checks++; if (!(cond)) fail(__LINE__, __VA_ARGS__); } while (0)
#define EXPECT_EQ(got, want) do { long long g_ = (long long)(got), w_ = (long long)(want); \
	checks++; if (g_ != w_) fail(__LINE__, "%s = %lld, want %lld", #got, g_, w_); } while (0)

static uint32_t ip(const char *s)
{
	uint32_t be = 0;

	parse_ipv4(s, &be);
	return be;
}

static const struct lease_rec *find(const struct lease_rec *r, size_t n, const char *addr)
{
	for (size_t i = 0; i < n; i++)
		if (r[i].ip == ip(addr))
			return &r[i];
	return NULL;
}

static int parse(enum lease_format f, const char *text, struct lease_rec **out, size_t *n)
{
	FILE *in = fmemopen((void *)text, strlen(text), "r");
	int err;

	if (!in)
		return -errno;
	err = leases_parse(f, in, out, n);
	fclose(in);
	return err;
}

static bool mac_is(const struct lease_rec *r, const char *s)
{
	uint8_t m[6];

	return r && parse_mac(s, m) == 0 && !memcmp(r->mac, m, 6);
}

static void test_dnsmasq(void)
{
	const char *text =
		"1794150000 52:54:00:aa:bb:01 10.0.0.11 host1 01:52:54:00:aa:bb:01\n"
		"0 52:54:00:aa:bb:02 10.0.0.12 * *\n"
		"duid 00:01:00:01:2c:5f:1a:2b:52:54:00:aa:bb:ff\n"
		"1794150000 12345678 fd00::5 host6 00:01:00:01:aa\n"
		"1794150000 06-52:54:00:aa:bb:03 10.0.0.13 * *\n"
		"garbage\n";
	struct lease_rec *r = NULL;
	size_t n = 0;

	current = "dnsmasq: IPv4 leases, infinite lease, IPv6 and non-Ethernet lines skipped";
	EXPECT_EQ(parse(LEASES_DNSMASQ, text, &r, &n), 0);
	EXPECT_EQ(n, 2);
	CHECK(mac_is(find(r, n, "10.0.0.11"), "52:54:00:aa:bb:01"), "10.0.0.11 missing");
	EXPECT_EQ(find(r, n, "10.0.0.11") ? find(r, n, "10.0.0.11")->expires : -1, 1794150000);
	EXPECT_EQ(find(r, n, "10.0.0.12") ? find(r, n, "10.0.0.12")->expires : -1, 0);
	free(r);

	current = "dnsmasq: empty file";
	r = NULL;
	EXPECT_EQ(parse(LEASES_DNSMASQ, "", &r, &n), 0);
	EXPECT_EQ(n, 0);
	free(r);
}

static void test_libvirt(void)
{
	const char *text =
		"[\n"
		"  {\n"
		"    \"ip-address\": \"192.168.122.36\",\n"
		"    \"mac-address\": \"52:54:00:6d:97:24\",\n"
		"    \"hostname\": \"vm \\\"one\\\"\",\n"
		"    \"client-id\": \"01:52:54:00:6d:97:24\",\n"
		"    \"expiry-time\": 1794150000\n"
		"  },\n"
		"  {\n"
		"    \"iaid\": \"1234\",\n"
		"    \"ip-address\": \"fd00::36\",\n"
		"    \"mac-address\": \"52:54:00:6d:97:25\",\n"
		"    \"expiry-time\": 1794150000\n"
		"  },\n"
		"  {\n"
		"    \"ip-address\": \"192.168.122.37\",\n"
		"    \"mac-address\": \"52:54:00:6d:97:26\",\n"
		"    \"expiry-time\": 0,\n"
		"    \"extra\": {\"nested\": [1, 2.5, \"x\", null], \"flag\": true}\n"
		"  }\n"
		"]\n";
	struct lease_rec *r = NULL;
	size_t n = 0;

	current = "libvirt: IPv4 entries, infinite lease, IPv6 skipped, unknown keys skipped";
	EXPECT_EQ(parse(LEASES_LIBVIRT, text, &r, &n), 0);
	EXPECT_EQ(n, 2);
	CHECK(mac_is(find(r, n, "192.168.122.36"), "52:54:00:6d:97:24"), "192.168.122.36 missing");
	EXPECT_EQ(find(r, n, "192.168.122.37") ? find(r, n, "192.168.122.37")->expires : -1, 0);
	free(r);

	current = "libvirt: empty array and empty file";
	r = NULL;
	EXPECT_EQ(parse(LEASES_LIBVIRT, "[ ]\n", &r, &n), 0);
	EXPECT_EQ(n, 0);
	free(r);
	r = NULL;
	EXPECT_EQ(parse(LEASES_LIBVIRT, "", &r, &n), 0);
	EXPECT_EQ(n, 0);
	free(r);

	current = "libvirt: truncated file is an error";
	r = NULL;
	EXPECT_EQ(parse(LEASES_LIBVIRT, "[ { \"ip-address\": \"10.0.0.1\"", &r, &n), -EINVAL);
}

static void test_kea(void)
{
	const char *text =
		"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"
		"10.1.0.10,aa:bb:cc:00:00:01,01:aa:bb:cc:00:00:01,3600,1794150000,1,0,0,h1,0,,0\n"
		"10.1.0.11,aa:bb:cc:00:00:02,,3600,1794150000,1,0,0,h2,0,,0\n"
		"10.1.0.11,aa:bb:cc:00:00:02,,0,1794150000,1,0,0,h2,0,,0\n"
		"10.1.0.12,aa:bb:cc:00:00:03,,3600,1794150000,1,0,0,h3,1,,0\n"
		"10.1.0.13,aa:bb:cc:00:00:04,,4294967295,1794150000,1,0,0,h4,0,{ \"a\": 1 },0\n"
		"10.1.0.14,aa:bb:cc:00:00:05,,3600,1794140000,1,0,0,h5,0,,0\n"
		"10.1.0.14,aa:bb:cc:00:00:06,,3600,1794150000,1,0,0,h5,0,,0\n"
		"10.1.0.15,,,3600,1794150000,1,0,0,h6,0,,0\n";
	struct lease_rec *r = NULL;
	size_t n = 0;

	current = "kea: last record per address wins; released and declined left out";
	EXPECT_EQ(parse(LEASES_KEA, text, &r, &n), 0);
	EXPECT_EQ(n, 3);
	CHECK(mac_is(find(r, n, "10.1.0.10"), "aa:bb:cc:00:00:01"), "10.1.0.10 missing");
	CHECK(!find(r, n, "10.1.0.11"), "released 10.1.0.11 kept");
	CHECK(!find(r, n, "10.1.0.12"), "declined 10.1.0.12 kept");
	EXPECT_EQ(find(r, n, "10.1.0.13") ? find(r, n, "10.1.0.13")->expires : -1, 0);
	CHECK(mac_is(find(r, n, "10.1.0.14"), "aa:bb:cc:00:00:06"), "10.1.0.14 not superseded");
	free(r);

	current = "kea: older files without a state column";
	r = NULL;
	EXPECT_EQ(parse(LEASES_KEA,
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname\n"
			"10.1.0.20,aa:bb:cc:00:00:20,,3600,1794150000,1,0,0,h\n", &r, &n), 0);
	EXPECT_EQ(n, 1);
	free(r);

	current = "kea: a file without the needed columns is an error";
	r = NULL;
	EXPECT_EQ(parse(LEASES_KEA, "address,duid\n", &r, &n), -EINVAL);
}

static void test_isc(void)
{
	const char *text =
		"# The format of this file is documented in the dhcpd.leases(5) manual page.\n"
		"authoring-byte-order little-endian;\n"
		"server-duid \"\\000\\001\\000\\001{}\";\n"
		"\n"
		"lease 10.2.0.10 {\n"
		"  starts 4 2026/11/05 10:00:00;\n"
		"  ends 5 2026/11/06 10:00:00;\n"
		"  cltt 4 2026/11/05 10:00:00;\n"
		"  binding state active;\n"
		"  next binding state free;\n"
		"  rewind binding state free;\n"
		"  hardware ethernet 00:16:3e:00:00:01;\n"
		"  uid \"\\001\\000\\026>}\\000\\001\";\n"
		"  client-hostname \"h1\";\n"
		"}\n"
		"lease 10.2.0.11 {\n"
		"  starts epoch 1794000000; # Wed\n"
		"  ends epoch 1794150000; # Thu\n"
		"  binding state active;\n"
		"  hardware ethernet 00:16:3e:00:00:02;\n"
		"}\n"
		"lease 10.2.0.11 {\n"
		"  ends epoch 1794150000;\n"
		"  binding state free;\n"
		"  hardware ethernet 00:16:3e:00:00:02;\n"
		"}\n"
		"lease 10.2.0.12 {\n"
		"  ends never;\n"
		"  binding state active;\n"
		"  hardware ethernet 00:16:3e:00:00:03;\n"
		"}\n"
		"host static1 {\n"
		"  dynamic;\n"
		"  hardware ethernet 00:16:3e:00:00:99;\n"
		"  fixed-address 10.2.0.99;\n"
		"}\n";
	struct lease_rec *r = NULL;
	struct tm tm = { .tm_year = 126, .tm_mon = 10, .tm_mday = 6, .tm_hour = 10 };
	size_t n = 0;

	current = "isc: active leases, UTC and epoch times, later blocks win";
	EXPECT_EQ(parse(LEASES_ISC, text, &r, &n), 0);
	EXPECT_EQ(n, 2);
	CHECK(mac_is(find(r, n, "10.2.0.10"), "00:16:3e:00:00:01"), "10.2.0.10 missing");
	EXPECT_EQ(find(r, n, "10.2.0.10") ? find(r, n, "10.2.0.10")->expires : -1, timegm(&tm));
	CHECK(!find(r, n, "10.2.0.11"), "freed 10.2.0.11 kept");
	EXPECT_EQ(find(r, n, "10.2.0.12") ? find(r, n, "10.2.0.12")->expires : -1, 0);
	CHECK(!find(r, n, "10.2.0.99"), "host declaration read as a lease");
	free(r);
}

static void test_find(void)
{
	struct lease_rec recs[] = {
		{ .mac = { 2, 0, 0, 0, 0, 1 }, .ip = ip("10.0.0.1"), .expires = 1000 },
		{ .mac = { 2, 0, 0, 0, 0, 2 }, .ip = ip("10.0.0.2"), .expires = 0 },
	};
	struct lease_source src = { .format = LEASES_DNSMASQ, .recs = recs, .n = 2 };
	const struct lease_source *from = NULL;
	const uint8_t m1[6] = { 2, 0, 0, 0, 0, 1 }, m2[6] = { 2, 0, 0, 0, 0, 2 };

	current = "lease_find: exact MAC and address, valid now";
	CHECK(lease_find(&src, 1, m1, ip("10.0.0.1"), 999, &from) == &recs[0], "valid lease not found");
	CHECK(from == &src, "source not reported");
	CHECK(!lease_find(&src, 1, m1, ip("10.0.0.1"), 1000, NULL), "expired lease found");
	CHECK(!lease_find(&src, 1, m2, ip("10.0.0.1"), 999, NULL), "lease found for another MAC");
	CHECK(!lease_find(&src, 1, m1, ip("10.0.0.2"), 999, NULL), "lease found for another address");
	CHECK(lease_find(&src, 1, m2, ip("10.0.0.2"), 2000000000, NULL) == &recs[1], "infinite lease not found");
}

static void test_source(void)
{
	char dir[] = "/tmp/lgtest.XXXXXX", path[64], spec[96];
	struct lease_source s;
	FILE *f;

	current = "lease_source_init: spec parsing";
	EXPECT_EQ(lease_source_init(&s, "dnsmasq:/var/lib/misc/dnsmasq.leases"), 0);
	EXPECT_EQ(s.format, LEASES_DNSMASQ);
	CHECK(!strcmp(s.path, "/var/lib/misc/dnsmasq.leases"), "path is %s", s.path);
	EXPECT_EQ(lease_source_init(&s, "isc:/x"), 0);
	EXPECT_EQ(s.format, LEASES_ISC);
	EXPECT_EQ(lease_source_init(&s, "bogus:/x"), -EINVAL);
	EXPECT_EQ(lease_source_init(&s, "dnsmasq:"), -EINVAL);
	EXPECT_EQ(lease_source_init(&s, "/var/lib/misc/dnsmasq.leases"), -EINVAL);

	current = "lease_source_refresh: reload only on change, clear on removal";
	if (!mkdtemp(dir)) {
		fail(__LINE__, "mkdtemp: %s", strerror(errno));
		return;
	}
	snprintf(path, sizeof(path), "%s/leases", dir);
	snprintf(spec, sizeof(spec), "dnsmasq:%s", path);
	lg_log_level = LGL_ERROR;   /* the missing-file warning is expected */
	EXPECT_EQ(lease_source_init(&s, spec), 0);
	EXPECT_EQ(lease_source_refresh(&s), 0);
	EXPECT_EQ(s.n, 0);

	f = fopen(path, "w");
	fputs("0 52:54:00:aa:bb:01 10.0.0.11 * *\n", f);
	fclose(f);
	EXPECT_EQ(lease_source_refresh(&s), 1);
	EXPECT_EQ(s.n, 1);
	EXPECT_EQ(lease_source_refresh(&s), 0);

	f = fopen(path, "a");
	fputs("0 52:54:00:aa:bb:02 10.0.0.12 * *\n", f);
	fclose(f);
	EXPECT_EQ(lease_source_refresh(&s), 1);
	EXPECT_EQ(s.n, 2);

	unlink(path);
	EXPECT_EQ(lease_source_refresh(&s), 1);
	EXPECT_EQ(s.n, 0);
	rmdir(dir);
	lease_source_free(&s);
	lg_log_level = LGL_INFO;
}

static void test_decide(void)
{
	struct lease_rec lease = { .mac = { 2, 0, 0, 0, 0, 1 }, .ip = ip("10.0.0.5"), .expires = 0 };
	struct lg_lease cur = { .ip = ip("10.0.0.5") };
	const uint64_t now = 1000000000000ULL;

	current = "import_decide";
	EXPECT_EQ(import_decide(NULL, NULL, false, now), IMPORT_NONE);
	EXPECT_EQ(import_decide(&lease, NULL, true, now), IMPORT_CONFLICT);
	EXPECT_EQ(import_decide(&lease, NULL, false, now), IMPORT_INSERT);
	cur.expires_ns = now + 1;
	EXPECT_EQ(import_decide(&lease, &cur, false, now), IMPORT_CURRENT);
	cur.expires_ns = 0;
	EXPECT_EQ(import_decide(&lease, &cur, false, now), IMPORT_CURRENT);
	cur.expires_ns = now - 1;
	EXPECT_EQ(import_decide(&lease, &cur, false, now), IMPORT_REFRESH);
	cur.ip = ip("10.0.0.6");
	EXPECT_EQ(import_decide(&lease, &cur, false, now), IMPORT_OTHER_IP);

	current = "import_candidate";
	CHECK(import_candidate(LG_R_NO_BINDING), "no_binding");
	CHECK(import_candidate(LG_R_EXPIRED), "expired");
	CHECK(import_candidate(LG_R_ARP_UNBOUND), "arp_unbound");
	CHECK(!import_candidate(LG_R_IP_MISMATCH), "ip_mismatch");
	CHECK(!import_candidate(LG_R_DHCP_SERVER), "dhcp_server");
}

static void test_conflict(void)
{
	struct lg_key me = { .ifindex = 4, .mac = { 2, 0, 0, 0, 0, 1 } };
	struct lg_key other = { .ifindex = 5, .mac = { 2, 0, 0, 0, 0, 1 } };
	const uint64_t now = 1000000000000ULL;
	struct lg_binding snap[2] = {
		{ .key = other, .ip = ip("10.0.0.5"), .expires_ns = now + 1 },
		{ .key = me, .ip = ip("10.0.0.7"), .expires_ns = now + 1 },
	};

	current = "import_conflict";
	CHECK(import_conflict(snap, 2, &me, ip("10.0.0.5"), now), "valid binding on another port ignored");
	CHECK(!import_conflict(snap, 2, &me, ip("10.0.0.7"), now), "own binding counted as conflict");
	CHECK(!import_conflict(snap, 2, &me, ip("10.0.0.9"), now), "unbound address conflicts");
	snap[0].expires_ns = now - 1;
	CHECK(!import_conflict(snap, 2, &me, ip("10.0.0.5"), now), "expired binding counted");
	snap[0].is_static = true;
	CHECK(import_conflict(snap, 2, &me, ip("10.0.0.5"), now), "static binding ignored");
	snap[0].is_static = false;
	snap[0].expires_ns = 0;
	CHECK(import_conflict(snap, 2, &me, ip("10.0.0.5"), now), "infinite binding ignored");
}

static void test_value(void)
{
	struct lease_rec lease = { .ip = ip("10.0.0.5"), .expires = 0 };
	struct lg_lease v;
	const uint64_t nowb = 5000000000ULL;

	current = "import_value";
	import_value(&lease, 1000, nowb, &v);
	EXPECT_EQ(v.ip, ip("10.0.0.5"));
	EXPECT_EQ(v.expires_ns, 0);
	EXPECT_EQ(v.lease_secs, LG_INFINITE_LEASE);
	EXPECT_EQ(v.flags, LG_LEASE_IMPORTED);
	lease.expires = 1600;
	import_value(&lease, 1000, nowb, &v);
	EXPECT_EQ(v.lease_secs, 600);
	EXPECT_EQ(v.expires_ns, nowb + 600ULL * 1000000000ULL);
	EXPECT_EQ(v.bound_ns, nowb);
}

int main(void)
{
	test_dnsmasq();
	test_libvirt();
	test_kea();
	test_isc();
	test_find();
	test_source();
	test_decide();
	test_conflict();
	test_value();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
