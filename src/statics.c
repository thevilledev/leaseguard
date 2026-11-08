// SPDX-License-Identifier: MIT
#include "statics.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

int statics_load(const char *path, struct static_entry **out, size_t *n)
{
	struct static_entry *res = NULL;
	size_t cap = 0, cnt = 0;
	char line[512];
	int lineno = 0, err = 0;
	FILE *f;

	f = fopen(path, "re");
	if (!f) {
		err = -errno;
		log_error("msg=\"cannot open static bindings\" path=%s error=\"%s\"", path, strerror(-err));
		return err;
	}

	while (fgets(line, sizeof(line), f)) {
		char *tok[5] = {0}, *save = NULL, *hash;
		struct static_entry e = {0};
		int ntok = 0;
		uint32_t vlan = 0;

		lineno++;
		hash = strchr(line, '#');
		if (hash)
			*hash = '\0';
		for (char *t = strtok_r(line, " \t\r\n", &save); t && ntok < 5;
		     t = strtok_r(NULL, " \t\r\n", &save))
			tok[ntok++] = t;
		if (ntok == 0)
			continue;
		if (ntok < 3 || ntok > 4) {
			log_error("msg=\"static bindings: want PORT MAC IP [VLAN]\" path=%s line=%d", path, lineno);
			err = -EINVAL;
			break;
		}
		if (strlen(tok[0]) >= sizeof(e.port)) {
			log_error("msg=\"static bindings: port name too long\" path=%s line=%d", path, lineno);
			err = -EINVAL;
			break;
		}
		strcpy(e.port, tok[0]);
		if (parse_mac(tok[1], e.mac)) {
			log_error("msg=\"static bindings: bad MAC\" path=%s line=%d value=%s", path, lineno, tok[1]);
			err = -EINVAL;
			break;
		}
		if (parse_ipv4(tok[2], &e.ip) || e.ip == 0) {
			log_error("msg=\"static bindings: bad IPv4 address\" path=%s line=%d value=%s", path, lineno, tok[2]);
			err = -EINVAL;
			break;
		}
		if (ntok == 4 && (parse_u32(tok[3], &vlan) || vlan > 4094)) {
			log_error("msg=\"static bindings: bad VLAN\" path=%s line=%d value=%s", path, lineno, tok[3]);
			err = -EINVAL;
			break;
		}
		e.vlan = (uint16_t)vlan;
		if (grow((void **)&res, &cap, cnt + 1, sizeof(*res))) {
			err = -ENOMEM;
			break;
		}
		res[cnt++] = e;
	}
	fclose(f);
	if (err) {
		free(res);
		return err;
	}
	*out = res;
	*n = cnt;
	return 0;
}
