# SPDX-License-Identifier: MIT
#
#   make            build build/leaseguard (the datapath is embedded)
#   make unit       lease file and import tests (no privileges)
#   make test       datapath tests through the verifier (root)
#   make e2e        end-to-end tests in network namespaces (root)
#   make interop    against real DHCP servers and clients (root); pick with
#                   SERVERS=, CLIENTS= and RELAY=1
#   make install    install to $(DESTDIR)$(PREFIX)

CC      ?= cc
CLANG   ?= clang
PREFIX  ?= /usr/local
ARCH    := $(shell uname -m)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

BUILD   := build
BPF_OBJ := $(BUILD)/leaseguard.bpf.o
BIN     := $(BUILD)/leaseguard
TESTBIN := $(BUILD)/test_datapath
UNITBIN := $(BUILD)/test_leases

CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Wshadow -Wno-unused-parameter \
	   -D_GNU_SOURCE -Ibpf -Isrc -DLG_VERSION='"$(VERSION)"'
LDLIBS  += -lbpf

# The kernel UAPI headers want <asm/types.h>, which lives in the
# multiarch directory on Debian and Ubuntu.
BPF_CFLAGS := -O2 -g -target bpf -mcpu=v3 -Wall -Werror -Ibpf \
	      -I/usr/include/$(ARCH)-linux-gnu

SRCS := src/main.c src/daemon.c src/dp.c src/import.c src/leases.c src/nl.c src/statics.c \
	src/util.c
OBJS := $(SRCS:src/%.c=$(BUILD)/%.o) $(BUILD)/bpf_obj.o

.PHONY: all unit test e2e interop install clean

all: $(BIN)

$(BUILD):
	mkdir -p $@

$(BPF_OBJ): bpf/leaseguard.bpf.c bpf/leaseguard.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/%.o: src/%.c src/*.h bpf/leaseguard.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/bpf_obj.o: src/bpf_obj.S $(BPF_OBJ) | $(BUILD)
	$(CC) -c -DLG_BPF_OBJ='"$(abspath $(BPF_OBJ))"' $< -o $@

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(TESTBIN): tests/test_datapath.c tests/pkt.h bpf/leaseguard.h | $(BUILD)
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

UNIT_SRCS := src/leases.c src/import.c src/util.c

$(UNITBIN): tests/test_leases.c $(UNIT_SRCS) src/*.h bpf/leaseguard.h | $(BUILD)
	$(CC) $(CFLAGS) tests/test_leases.c $(UNIT_SRCS) -o $@

unit: $(UNITBIN)
	./$(UNITBIN)

test: $(TESTBIN) $(BPF_OBJ)
	LG_BPF_OBJ=$(BPF_OBJ) ./$(TESTBIN)

e2e: $(BIN)
	LEASEGUARD=$(abspath $(BIN)) tests/e2e.sh

SERVERS ?= dnsmasq kea isc libvirt
CLIENTS ?= udhcpc dhclient dhcpcd
RELAY   ?= 0

# Every SERVERS x CLIENTS pair; pairs whose tools are missing are skipped
# (exit 77) unless REQUIRE=1.
interop: $(BIN)
	@fail=; for s in $(SERVERS); do for c in $(CLIENTS); do \
		LEASEGUARD=$(abspath $(BIN)) SERVER=$$s CLIENT=$$c RELAY=$(RELAY) \
			tests/interop.sh; rc=$$?; \
		[ $$rc -eq 0 ] || [ $$rc -eq 77 ] || fail="$$fail $$s/$$c"; \
	done; done; \
	if [ -n "$$fail" ]; then echo; echo "interop failed:$$fail"; exit 1; fi

install: $(BIN)
	install -D -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/sbin/leaseguard

clean:
	rm -rf $(BUILD)
