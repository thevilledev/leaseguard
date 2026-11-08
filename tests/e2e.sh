#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# End-to-end test: a Linux bridge in its own network namespace, a dnsmasq
# DHCP server on a trusted port, a client and an attacker on untrusted
# ports, and leaseguard in between.
#
#   [srv: dnsmasq 10.99.0.1] --srv0--+
#                                    br0  (leaseguard, srv0 trusted)
#   [c1: udhcpc]             --c1p---+
#   [c2: attacker]           --c2p---+
#
# Needs root, iproute2, util-linux (nsenter), dnsmasq, busybox (udhcpc), ping
# and python3. ATTACH=tc runs the same test with legacy tc attachment; KEEP=1
# keeps the logs and a snapshot of `bindings` and `stats` in the temp dir.
#
# leaseguard runs under `nsenter --net`, not `ip netns exec`: the latter
# remounts /sys, which hides the bpf filesystem the pinned maps live on.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
LG=${LEASEGUARD:-$HERE/../build/leaseguard}
ATTACH=${ATTACH:-auto}
NETPKT="python3 $HERE/netpkt.py"

P=lge2e$$
NS_BR=$P-br NS_SRV=$P-srv NS_C1=$P-c1 NS_C2=$P-c2 NS_C3=$P-c3
MAC_SRV=02:00:00:00:00:01 MAC_C1=02:00:00:00:00:c1 MAC_C2=02:00:00:00:00:c2 MAC_C3=02:00:00:00:00:c3
SRV_IP=10.99.0.1
PIN=/sys/fs/bpf/leaseguard-e2e-$$
TMP=$(mktemp -d)
LG_PID= DNSMASQ_PID= ROGUE_PID= LGLOG= STARTS=0
failures=0 checks=0 skipped=0

# --- helpers ----------------------------------------------------------------

log()  { printf '\n== %s\n' "$*"; }
ok()   { checks=$((checks + 1)); printf '  ok   %s\n' "$*"; }
bad()  { checks=$((checks + 1)); failures=$((failures + 1)); printf '  FAIL %s\n' "$*"; }
skip() { skipped=$((skipped + 1)); printf '  skip %s\n' "$*"; }
check()        { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
check_not()    { local d=$1; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }

# wait_until SECONDS CMD...: poll until CMD succeeds.
wait_until() {
	local deadline=$((SECONDS + $1)); shift
	until "$@" >/dev/null 2>&1; do
		[ $SECONDS -ge $deadline ] && return 1
		sleep 0.2
	done
}

in_ns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
br_ns() { nsenter --net="/run/netns/$NS_BR" "$@"; }
lg()    { br_ns "$LG" "$@" --pin-dir "$PIN"; }

counter() { lg stats | awk -v r="$1" '$1 == r { print $2 }'; }
counter_positive() { [ "$(counter "$1")" -gt 0 ]; }
has_binding() { lg bindings | grep -Eq "$1"; }

# counter_grows NAME CMD...: CMD runs, then NAME must have increased.
counter_grows() {
	local name=$1; shift
	local before after
	before=$(counter "$name")
	"$@" >/dev/null 2>&1 || true
	sleep 0.3
	after=$(counter "$name")
	if [ "$after" -gt "$before" ]; then
		ok "counter $name grew ($before -> $after)"
	else
		bad "counter $name did not grow ($before -> $after)"
	fi
}

ping_from() { in_ns "$1" ping -c 1 -W "${3:-2}" ${2:+-I "$2"} "$SRV_IP"; }

# sniffed NS IFACE KIND SRC_MAC SEND_ARGS...: send a frame from c2, report
# whether it reached the server's interface.
sniffed() {
	local ready=$TMP/sniff.ready rc=0
	rm -f "$ready"
	in_ns "$NS_SRV" $NETPKT sniff eth0 "$1" "$MAC_C2" 2 "$ready" &
	local pid=$!
	wait_until 5 test -e "$ready" || true
	in_ns "$NS_C2" $NETPKT send eth0 "$1" "$MAC_C2" "${@:2}"
	wait "$pid" || rc=$?
	return $rc
}

dhcp() {  # dhcp NS [UDHCPC_ARGS...]: run one DHCP exchange, print the address
	local ns=$1 out=$TMP/$1.ip
	shift
	rm -f "$out"
	in_ns "$ns" env DHCP_OUT="$out" busybox udhcpc -i eth0 -f -q -n -t 6 -T 1 "$@" \
		-s "$TMP/udhcpc.sh" >>"$TMP/udhcpc.log" 2>&1 || return 1
	cat "$out"
}

start_leaseguard() {  # start_leaseguard [EXTRA_RUN_ARGS...]
	STARTS=$((STARTS + 1))
	LGLOG=$TMP/leaseguard.$STARTS.log
	# nsenter execs leaseguard, so $! is the daemon itself.
	nsenter --net="/run/netns/$NS_BR" "$LG" run --bridge br0 --trusted srv0 \
		--mode enforce --static "$TMP/static" --attach "$ATTACH" --interval 1 \
		--pin-dir "$PIN" -v "$@" >"$LGLOG" 2>&1 &
	LG_PID=$!
	wait_until 10 grep -q "msg=started" "$LGLOG"
}

stop_leaseguard() {
	[ -n "$LG_PID" ] || return 0
	kill -TERM "$LG_PID" 2>/dev/null || true
	wait "$LG_PID" 2>/dev/null || true
	LG_PID=
}

cleanup() {
	local rc=$?
	set +e
	stop_leaseguard
	for pid in $DNSMASQ_PID $ROGUE_PID; do kill "$pid" 2>/dev/null; done
	for ns in $NS_BR $NS_SRV $NS_C1 $NS_C2 $NS_C3; do
		ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
		ip netns del "$ns" 2>/dev/null
	done
	"$LG" reset --pin-dir "$PIN" >/dev/null 2>&1
	if [ "$failures" -ne 0 ] || [ "$rc" -ne 0 ]; then
		for f in "$TMP"/leaseguard.*.log; do echo; echo "--- $(basename "$f")"; cat "$f"; done
		echo "--- dnsmasq log"; tail -n 30 "$TMP/dnsmasq.log" 2>/dev/null
		echo "--- udhcpc log"; tail -n 30 "$TMP/udhcpc.log" 2>/dev/null
	fi
	if [ -n "${KEEP:-}" ]; then echo "kept $TMP"; else rm -rf "$TMP"; fi
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { echo "e2e.sh needs root"; exit 77; }
for t in ip nsenter dnsmasq busybox ping python3; do
	command -v "$t" >/dev/null || { echo "e2e.sh needs $t"; exit 77; }
done

# --- topology ---------------------------------------------------------------

log "setting up (attach=$ATTACH)"
for ns in $NS_BR $NS_SRV $NS_C1 $NS_C2; do
	ip netns add "$ns"
	ip -n "$ns" link set lo up
done
# Without multicast snooping the bridge floods IPv6 multicast even on hosts
# that have IPv6 disabled, which the RA tests rely on.
ip -n "$NS_BR" link add br0 type bridge mcast_snooping 0
ip -n "$NS_BR" link set br0 up

# port PORT NS MAC: veth pair with PORT on the bridge and eth0 in NS.
port() {
	ip -n "$NS_BR" link add "$1" type veth peer name eth0 netns "$2"
	ip -n "$2" link set eth0 address "$3" up
	ip -n "$NS_BR" link set "$1" master br0 up
}
port srv0 "$NS_SRV" "$MAC_SRV"
port c1p "$NS_C1" "$MAC_C1"
port c2p "$NS_C2" "$MAC_C2"
ip -n "$NS_SRV" addr add "$SRV_IP/24" dev eth0

cat >"$TMP/udhcpc.sh" <<'EOF'
#!/bin/sh
case "$1" in
deconfig) ip addr flush dev "$interface" scope global ;;
bound|renew)
	ip addr flush dev "$interface" scope global
	ip addr add "$ip/${mask:-24}" dev "$interface"
	echo "$ip" >"$DHCP_OUT" ;;
esac
EOF
chmod +x "$TMP/udhcpc.sh"
: >"$TMP/static"

# `ip netns exec` execs its command, so $! is dnsmasq itself.
ip netns exec "$NS_SRV" dnsmasq --no-daemon --conf-file=/dev/null --user=root --port=0 \
	--interface=eth0 --bind-interfaces --dhcp-authoritative \
	--dhcp-range=10.99.0.100,10.99.0.150,255.255.255.0,2m \
	--dhcp-leasefile="$TMP/leases" --log-dhcp --log-facility="$TMP/dnsmasq.log" &
DNSMASQ_PID=$!

start_leaseguard || { bad "leaseguard started"; exit 1; }
ok "leaseguard started"
check "c1p attached" wait_until 5 grep -q "msg=attached port=c1p" "$LGLOG"
check "c2p attached" wait_until 5 grep -q "msg=attached port=c2p" "$LGLOG"
check_not "trusted srv0 left alone" grep -q "port=srv0" "$LGLOG"
if [ "$ATTACH" != auto ]; then
	check "attached via $ATTACH" grep -q "msg=attached port=c1p ifindex=[0-9]* via=$ATTACH\$" "$LGLOG"
fi

# --- DHCP snooping and IPv4 source guard ------------------------------------

log "DHCP snooping"
C1_IP=$(dhcp "$NS_C1") || true
case "$C1_IP" in 10.99.0.*) ok "c1 got a lease ($C1_IP)" ;; *) bad "c1 got a lease ('$C1_IP')"; exit 1 ;; esac
check "binding listed for c1p" has_binding "^c1p +0 +$MAC_C1 +$C1_IP +dhcp +in "
check "bind event logged" grep -q "msg=bind port=c1p vlan=0 mac=$MAC_C1 ip=$C1_IP" "$LGLOG"
check_not "no binding leaked to c2p" has_binding "^c2p "
check "c1 reaches the server from its lease" ping_from "$NS_C1"

# With the broadcast flag the server floods its replies to every port; only
# the port that asked may bind.
before=$(counter reply_unsolicited)
ip=$(dhcp "$NS_C1" -B) || true
case "$ip" in 10.99.0.*) ok "c1 lease with broadcast replies ($ip)" ;; *) bad "c1 lease with broadcast replies ('$ip')" ;; esac
unsolicited() { [ "$(counter reply_unsolicited)" -gt "$before" ]; }
check "flooded reply reached c2p and was ignored" unsolicited
check_not "still no binding on c2p" has_binding "^c2p "
C1_IP=$ip

log "IPv4 source guard"
# A static neighbor entry makes the spoofed packets go out as IPv4 instead of
# stopping at ARP inspection.
ip -n "$NS_C1" neigh replace "$SRV_IP" lladdr "$MAC_SRV" dev eth0 nud permanent
ip -n "$NS_C1" addr add 10.99.0.200/24 dev eth0
check_not "c1 cannot use an address it was not given" ping_from "$NS_C1" 10.99.0.200 1
counter_grows ip_mismatch ping_from "$NS_C1" 10.99.0.200 1
ip -n "$NS_C1" addr del 10.99.0.200/24 dev eth0
ip -n "$NS_C1" neigh del "$SRV_IP" dev eth0

ip -n "$NS_C2" addr add 10.99.0.201/24 dev eth0
check_not "c2 without a lease cannot reach the server" ping_from "$NS_C2" "" 1
counter_grows arp_unbound ping_from "$NS_C2" "" 1
# Skip ARP: send IPv4 straight at the server's MAC.
ip -n "$NS_C2" neigh replace "$SRV_IP" lladdr "$MAC_SRV" dev eth0 nud permanent
counter_grows no_binding ping_from "$NS_C2" "" 1

log "cloning c1's MAC and address on another port"
ip -n "$NS_C2" addr flush dev eth0
ip -n "$NS_C2" link set eth0 address "$MAC_C1"
ip -n "$NS_C2" addr add "$C1_IP/24" dev eth0
ip -n "$NS_C2" neigh replace "$SRV_IP" lladdr "$MAC_SRV" dev eth0 nud permanent
check_not "clone on c2p is dropped (bindings are per port)" ping_from "$NS_C2" "" 1
check "c1 still reaches the server" ping_from "$NS_C1"
ip -n "$NS_C2" addr flush dev eth0
ip -n "$NS_C2" link set eth0 address "$MAC_C2"
ip -n "$NS_C2" addr add 10.99.0.201/24 dev eth0
ip -n "$NS_C2" neigh replace "$SRV_IP" lladdr "$MAC_SRV" dev eth0 nud permanent

# --- ARP inspection -----------------------------------------------------------

log "ARP inspection"
check_not "gratuitous ARP claiming c1's address never reaches the server" sniffed garp "$C1_IP"
counter_grows arp_unbound in_ns "$NS_C2" $NETPKT send eth0 garp "$MAC_C2" "$C1_IP"

# --- rogue servers ------------------------------------------------------------

log "rogue DHCP server"
ip -n "$NS_C2" addr add 10.66.0.1/24 dev eth0
ip netns exec "$NS_C2" dnsmasq --no-daemon --conf-file=/dev/null --user=root --port=0 \
	--interface=eth0 --bind-interfaces --dhcp-authoritative --no-ping \
	--dhcp-range=10.66.0.100,10.66.0.150,255.255.255.0,2m \
	--dhcp-leasefile="$TMP/rogue.leases" --log-facility="$TMP/rogue.log" &
ROGUE_PID=$!
sleep 1
before=$(counter dhcp_server)
for i in 1 2 3; do
	ip=$(dhcp "$NS_C1") || true
	case "$ip" in 10.99.0.*) ok "c1 lease $i comes from the real server ($ip)" ;; *) bad "c1 lease $i: '$ip'" ;; esac
done
rogue_dropped() { [ "$(counter dhcp_server)" -gt "$before" ]; }
check "rogue offers were dropped at c2p" wait_until 5 rogue_dropped
check "the rogue server did answer" grep -q DHCPOFFER "$TMP/rogue.log"
kill "$ROGUE_PID"; wait "$ROGUE_PID" 2>/dev/null || true; ROGUE_PID=
ip -n "$NS_C2" addr del 10.66.0.1/24 dev eth0
C1_IP=$(dhcp "$NS_C1")

log "IPv6 router advertisement guard"
# A kernel booted with IPv6 disabled does not bridge IPv6 at all, so these
# frames could not arrive either way. The unit tests still cover the logic.
if [ -d /proc/sys/net/ipv6 ]; then
	HAVE_IPV6=1
	check_not "RA from c2 never reaches the server" sniffed ra
	check "ICMPv6 echo from c2 still passes" sniffed echo6
else
	HAVE_IPV6=
	skip "RA and ICMPv6 delivery: this kernel has IPv6 disabled"
fi
counter_grows ipv6_router in_ns "$NS_C2" $NETPKT send eth0 ra "$MAC_C2"

# --- monitor mode -------------------------------------------------------------

log "monitor mode"
lg mode monitor >/dev/null
check "c2 passes in monitor mode" ping_from "$NS_C2"
check "would-drop is logged" grep -q 'msg="would drop" reason=' "$LGLOG"
# The same frames the guards drop get through now, so the sniffer works.
check "gratuitous ARP gets through in monitor mode" sniffed garp "$C1_IP"
if [ -n "$HAVE_IPV6" ]; then
	check "RA gets through in monitor mode" sniffed ra
fi
lg mode enforce >/dev/null
check_not "c2 is dropped again in enforce mode" ping_from "$NS_C2" "" 1

# --- release ------------------------------------------------------------------

log "DHCPRELEASE"
rm -f "$TMP/c1.ip"
ip netns exec "$NS_C1" env DHCP_OUT="$TMP/c1.ip" busybox udhcpc -i eth0 -f -R -t 6 -T 1 \
	-s "$TMP/udhcpc.sh" >>"$TMP/udhcpc.log" 2>&1 &
UDHCPC=$!
wait_until 10 test -s "$TMP/c1.ip" || true
C1_IP=$(cat "$TMP/c1.ip")
check "c1 bound before release" ping_from "$NS_C1"
kill -TERM "$UDHCPC"; wait "$UDHCPC" 2>/dev/null || true
check "unbind event for the release" wait_until 5 grep -q "msg=unbind port=c1p vlan=0 mac=$MAC_C1 ip=$C1_IP reason=release" "$LGLOG"
ip -n "$NS_C1" addr add "$C1_IP/24" dev eth0
check_not "released address can no longer be used" ping_from "$NS_C1" "" 1
ip -n "$NS_C1" addr flush dev eth0 scope global

# --- restart keeps bindings -----------------------------------------------------

log "restart"
C1_IP=$(dhcp "$NS_C1")
stop_leaseguard
check "stopping detaches" grep -q "detached from all ports" "$LGLOG"
check "nothing enforced while stopped" ping_from "$NS_C2"
start_leaseguard
check "binding survived the restart" ping_from "$NS_C1"
check_not "c2 dropped again after the restart" ping_from "$NS_C2" "" 1

# --- importing leases from before leaseguard started ---------------------------

log "importing existing leases"
stop_leaseguard
lg reset >/dev/null
# c1 gets its lease while nothing is watching, as on a host where leaseguard
# is installed after the VMs booted.
C1_IP=$(dhcp "$NS_C1")
start_leaseguard --leases "dnsmasq:$TMP/leases"
check "lease file read" grep -q "msg=\"importing leases\" format=dnsmasq path=$TMP/leases leases=[1-9]" "$LGLOG"
check_not "no binding until c1 sends something" has_binding "^c1p "
check "c1 gets in once its lease is imported" wait_until 10 ping_from "$NS_C1" "" 1
check "import logged" grep -q "msg=import port=c1p vlan=0 mac=$MAC_C1 ip=$C1_IP expires=in " "$LGLOG"
check "binding listed as imported" has_binding "^c1p +0 +$MAC_C1 +$C1_IP +import +in "
check "import counted" counter_positive import

# A clone of c1 on c2p matches the same lease, but the address is taken.
ip -n "$NS_C2" addr flush dev eth0
ip -n "$NS_C2" link set eth0 address "$MAC_C1"
ip -n "$NS_C2" addr add "$C1_IP/24" dev eth0
ip -n "$NS_C2" neigh replace "$SRV_IP" lladdr "$MAC_SRV" dev eth0 nud permanent
check_not "clone on c2p is not imported" ping_from "$NS_C2" "" 1
check_not "no binding on c2p" has_binding "^c2p "
ip -n "$NS_C2" addr flush dev eth0
ip -n "$NS_C2" link set eth0 address "$MAC_C2"
ip -n "$NS_C2" addr add 10.99.0.201/24 dev eth0
ip -n "$NS_C2" neigh replace "$SRV_IP" lladdr "$MAC_SRV" dev eth0 nud permanent
check_not "c2 without a lease is not imported" ping_from "$NS_C2" "" 1

# --- port hotplug and static bindings -------------------------------------------

log "hotplug and static bindings"
ip netns add "$NS_C3"
port c3p "$NS_C3" "$MAC_C3"
ip -n "$NS_C3" addr add 10.99.0.210/24 dev eth0
check "new port attached automatically" wait_until 5 grep -q "msg=attached port=c3p" "$LGLOG"
check_not "c3 has no binding yet" ping_from "$NS_C3" "" 1
echo "c3p $MAC_C3 10.99.0.210  # static host" >"$TMP/static"
kill -HUP "$LG_PID"
check "static binding lets c3 in" wait_until 5 ping_from "$NS_C3" "" 1
check "static binding listed" has_binding "^c3p +0 +$MAC_C3 +10.99.0.210 +static +never"
if [ -n "${KEEP:-}" ]; then
	lg bindings >"$TMP/bindings.txt"
	lg stats >"$TMP/stats.txt"
fi
ip -n "$NS_BR" link del c3p
check "removed port detached" wait_until 5 grep -q 'msg=detached port=c3p ifindex=[0-9]* reason="removed"' "$LGLOG"

# --- summary --------------------------------------------------------------------

stop_leaseguard
echo
echo "$checks checks, $failures failures, $skipped skipped"
[ "$failures" -eq 0 ]
