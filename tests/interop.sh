#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Interoperability test: leaseguard between a real DHCP server and a real
# DHCP client, one pair per run.
#
#   SERVER=dnsmasq|kea|isc|libvirt   (default dnsmasq)
#   CLIENT=udhcpc|dhclient|dhcpcd    (default udhcpc)
#   RELAY=1                          put the server behind an ISC dhcrelay
#
#   [server 10.99.0.1] --up0--+
#                             br0 --c1p-- [client]
#                                 --c2p-- [attacker, no lease]
#
# With RELAY=1 the server sits on 10.98.0.0/24 behind a router that runs
# dhcrelay, and up0 leads to the router (10.99.0.1) instead:
#
#   [server 10.98.0.1] -- [10.98.0.2 dhcrelay 10.99.0.1] --up0-- br0 ...
#
# up0 is trusted. Each run checks that the client's lease is snooped and
# enforced, that a renewal (unicast REQUEST, ACK) refreshes the binding, that
# DHCPRELEASE removes it, and that the server's lease file can be imported
# for a client that got its lease while leaseguard was not running.
#
# `libvirt` is dnsmasq with libvirt's leases helper as its --dhcp-script, so
# the lease file is libvirt's <bridge>.status JSON.
#
# Needs root, iproute2, util-linux (nsenter), ping and the server and client
# under test; dhcrelay (isc-dhcp-relay) with RELAY=1. Exits 77 if something is
# missing, unless REQUIRE=1. KEEP=1 keeps the temp dir; LOGDIR=DIR copies the
# logs there when the run fails.
#
# On Ubuntu, AppArmor confines dhcpd, dhclient and kea-dhcp4 to their
# standard paths, which breaks this test. Unload those profiles first, e.g.
# `apparmor_parser -R /etc/apparmor.d/usr.sbin.dhcpd`.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
LG=${LEASEGUARD:-$HERE/../build/leaseguard}
SERVER=${SERVER:-dnsmasq}
CLIENT=${CLIENT:-udhcpc}
RELAY=${RELAY:-0}
[ "$RELAY" = 0 ] && RELAY=
NAME="$SERVER${RELAY:+ via relay} / $CLIENT"

P=lgio$$
NS_BR=$P-br NS_SRV=$P-srv NS_RLY=$P-rly NS_C1=$P-c1 NS_C2=$P-c2
# The server's and the clients' interfaces get a unique name: dhcpcd and
# libvirt's helper name files in the shared /var/lib and /run after them.
IF=$P
MAC_UP=02:00:00:00:01:01 MAC_C1=02:00:00:00:01:c1 MAC_C2=02:00:00:00:01:c2
GW=10.99.0.1                # the server, or the relay with RELAY=1
SRV_IP=$GW
[ -n "$RELAY" ] && SRV_IP=10.98.0.1
LEASE_SECS=120              # dnsmasq's minimum
PIN=/sys/fs/bpf/leaseguard-interop-$$
TMP=$(mktemp -d)
LIBVIRT_STATUS=/var/lib/libvirt/dnsmasq/$P.status
LG_PID= LGLOG= STARTS=0 CLIENT_PID=
failures=0 checks=0

# --- helpers ----------------------------------------------------------------

log()  { printf '\n== %s\n' "$*"; }
ok()   { checks=$((checks + 1)); printf '  ok   %s\n' "$*"; }
bad()  { checks=$((checks + 1)); failures=$((failures + 1)); printf '  FAIL %s\n' "$*"; }
check()     { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
check_not() { local d=$1; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }

wait_until() {
	local deadline=$((SECONDS + $1)); shift
	until "$@" >/dev/null 2>&1; do
		[ $SECONDS -ge $deadline ] && return 1
		sleep 0.2
	done
}

in_ns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
lg()    { nsenter --net="/run/netns/$NS_BR" "$LG" "$@" --pin-dir "$PIN"; }

counter() { lg stats | awk -v r="$1" '$1 == r { print $2 }'; }
has_binding() { lg bindings | grep -Eq "$1"; }
binds() { grep -c "msg=bind port=c1p vlan=0 mac=$MAC_C1 ip=$1 " "$LGLOG" || true; }

ping_from() { in_ns "$1" ping -c 1 -W "${3:-2}" ${2:+-I "$2"} "$GW"; }

# The client's address, once it has one.
client_ip() {
	ip -n "$NS_C1" -4 -o addr show dev "$IF" scope global |
		awk '{ sub("/.*", "", $4); print $4; exit }' | grep .
}

# Kill everything in a namespace: no release, no deconfiguration.
ns_kill() {
	local pids
	pids=$(ip netns pids "$1" 2>/dev/null) || return 0
	[ -n "$pids" ] || return 0
	kill -KILL $pids 2>/dev/null
	# Reap our own children quietly, so bash does not report them killed.
	for pid in $pids; do wait "$pid" 2>/dev/null || true; done
	wait_until 5 test -z "$(ip netns pids "$1")" || true
}

skip_run() {
	echo "interop.sh ($NAME): $*"
	[ -n "${REQUIRE:-}" ] && exit 1
	exit 77
}
need() { for t; do command -v "$t" >/dev/null || skip_run "needs $t"; done; }

# --- DHCP servers -------------------------------------------------------------

start_dnsmasq() {  # start_dnsmasq [EXTRA_ARGS...]
	# T1 is lowered so that clients that follow it renew during the test.
	ip netns exec "$NS_SRV" dnsmasq --keep-in-foreground --conf-file=/dev/null --user=root --port=0 \
		--interface="$IF" --bind-interfaces --dhcp-authoritative --no-ping \
		--dhcp-range=10.99.0.100,10.99.0.150,255.255.255.0,${LEASE_SECS}s \
		--dhcp-option=option:router,$GW --dhcp-option=option:T1,6 \
		--dhcp-option=option:T2,10 --log-dhcp --log-facility="$TMP/server.log" "$@" \
		2>>"$TMP/server.log" &
	wait_until 10 grep -q "DHCP, IP range" "$TMP/server.log"
}

start_server() {
	case $SERVER in
	dnsmasq)
		LEASES=dnsmasq:$TMP/dnsmasq.leases
		start_dnsmasq --dhcp-leasefile="$TMP/dnsmasq.leases"
		;;
	libvirt)
		# The helper names the status file after DNSMASQ_INTERFACE, or at
		# startup after VIR_BRIDGE_NAME. Under libvirt both are the bridge.
		LEASES=libvirt:$LIBVIRT_STATUS
		mkdir -p "$(dirname "$LIBVIRT_STATUS")"
		VIR_BRIDGE_NAME=$IF start_dnsmasq --leasefile-ro \
			--dhcp-script=/usr/lib/libvirt/libvirt_leaseshelper
		;;
	kea)
		LEASES=kea:$TMP/kea-leases4.csv
		local socket=raw
		[ -n "$RELAY" ] && socket=udp
		cat >"$TMP/kea.json" <<-EOF
		{ "Dhcp4": {
		    "interfaces-config": { "interfaces": [ "$IF" ], "dhcp-socket-type": "$socket" },
		    "lease-database": { "type": "memfile", "persist": true,
		                        "name": "$TMP/kea-leases4.csv", "lfc-interval": 0 },
		    "valid-lifetime": $LEASE_SECS, "renew-timer": 6, "rebind-timer": 10,
		    "subnet4": [ { "id": 1, "subnet": "10.99.0.0/24",
		                   "pools": [ { "pool": "10.99.0.100 - 10.99.0.150" } ],
		                   "option-data": [ { "name": "routers", "data": "$GW" } ] } ]
		} }
		EOF
		# Kea 2.6.3+ only writes lease files under its data directory.
		ip netns exec "$NS_SRV" env KEA_PIDFILE_DIR="$TMP" KEA_LOCKFILE_DIR="$TMP" \
			KEA_DHCP_DATA_DIR="$TMP" kea-dhcp4 -c "$TMP/kea.json" >"$TMP/server.log" 2>&1 &
		wait_until 10 grep -q DHCP4_STARTED "$TMP/server.log"
		;;
	isc)
		LEASES=isc:$TMP/dhcpd.leases
		cat >"$TMP/dhcpd.conf" <<-EOF
		authoritative;
		ping-check false;
		default-lease-time $LEASE_SECS;
		max-lease-time $LEASE_SECS;
		option dhcp-renewal-time 6;
		option dhcp-rebinding-time 10;
		subnet 10.99.0.0 netmask 255.255.255.0 {
		    range 10.99.0.100 10.99.0.150;
		    option routers $GW;
		}
		subnet 10.98.0.0 netmask 255.255.255.0 { }
		EOF
		: >"$TMP/dhcpd.leases"
		ip netns exec "$NS_SRV" dhcpd -4 -f -d -cf "$TMP/dhcpd.conf" -lf "$TMP/dhcpd.leases" \
			-pf "$TMP/dhcpd.pid" "$IF" >"$TMP/server.log" 2>&1 &
		wait_until 10 grep -q "Server starting service" "$TMP/server.log"
		;;
	*)
		echo "unknown SERVER $SERVER"; exit 2 ;;
	esac
}

# --- DHCP clients -------------------------------------------------------------
#
# client_start runs the client in the background until client_release or
# ns_kill. The address comes from the interface, not from the client.

client_start() {
	case $CLIENT in
	udhcpc)
		ip netns exec "$NS_C1" busybox udhcpc -i "$IF" -f -R -t 10 -T 1 -s "$TMP/client.sh" \
			>>"$TMP/client.log" 2>&1 & ;;
	dhclient)
		ip netns exec "$NS_C1" dhclient -4 -d -v -sf "$TMP/client.sh" -lf "$TMP/dhclient.leases" \
			-pf "$TMP/dhclient.pid" "$IF" >>"$TMP/client.log" 2>&1 & ;;
	dhcpcd)
		ip netns exec "$NS_C1" dhcpcd -4 -B -f "$TMP/dhcpcd.conf" "$IF" >>"$TMP/client.log" 2>&1 & ;;
	esac
	# `ip netns exec` execs its command, so $! is the client.
	CLIENT_PID=$!
	wait_until 30 client_ip
}

# udhcpc renews at half the lease time and ignores T1; SIGUSR1 renews now.
# The others follow the server's 6 s T1.
client_renew() {
	if [ "$CLIENT" = udhcpc ]; then kill -USR1 "$CLIENT_PID"; fi
}

client_release() {
	case $CLIENT in
	udhcpc)   kill -TERM "$CLIENT_PID" ;;    # -R: release on exit
	dhclient) in_ns "$NS_C1" dhclient -4 -r -v -sf "$TMP/client.sh" -lf "$TMP/dhclient.leases" \
			-pf "$TMP/dhclient.pid" "$IF" >>"$TMP/client.log" 2>&1 ;;
	dhcpcd)   in_ns "$NS_C1" dhcpcd -4 -k "$IF" >>"$TMP/client.log" 2>&1 ;;
	esac
	wait "$CLIENT_PID" 2>/dev/null || true
	CLIENT_PID=
}

write_client_config() {
	case $CLIENT in
	udhcpc)
		cat >"$TMP/client.sh" <<-'EOF'
		#!/bin/sh
		case "$1" in
		deconfig) ip addr flush dev "$interface" scope global ;;
		bound|renew)
			ip addr replace "$ip/${mask:-24}" dev "$interface"
			[ -n "$router" ] && ip route replace default via "${router%% *}" dev "$interface"
			;;
		esac
		exit 0
		EOF
		;;
	dhclient)
		cat >"$TMP/client.sh" <<-'EOF'
		#!/bin/sh
		case "$reason" in
		PREINIT) ip link set "$interface" up ;;
		BOUND|RENEW|REBIND|REBOOT)
			if [ -n "$old_ip_address" ] && [ "$old_ip_address" != "$new_ip_address" ]; then
				ip addr flush dev "$interface" scope global
			fi
			ip addr replace "$new_ip_address/$new_subnet_mask" dev "$interface"
			[ -n "$new_routers" ] && ip route replace default via "${new_routers%% *}" dev "$interface"
			;;
		EXPIRE|FAIL|RELEASE|STOP) ip addr flush dev "$interface" scope global ;;
		esac
		exit 0
		EOF
		;;
	dhcpcd)
		# dhcpcd configures the interface itself; no hooks, so it leaves
		# resolv.conf and the hostname alone.
		cat >"$TMP/dhcpcd.conf" <<-'EOF'
		noipv4ll
		script /bin/true
		EOF
		;;
	*)
		echo "unknown CLIENT $CLIENT"; exit 2 ;;
	esac
	[ -e "$TMP/client.sh" ] && chmod +x "$TMP/client.sh"
	return 0
}

# --- leaseguard ---------------------------------------------------------------

start_leaseguard() {  # start_leaseguard [EXTRA_RUN_ARGS...]
	STARTS=$((STARTS + 1))
	LGLOG=$TMP/leaseguard.$STARTS.log
	nsenter --net="/run/netns/$NS_BR" "$LG" run --bridge br0 --trusted up0 \
		--mode enforce --interval 1 --pin-dir "$PIN" -v "$@" >"$LGLOG" 2>&1 &
	LG_PID=$!
	wait_until 10 grep -q "msg=started" "$LGLOG" &&
		wait_until 5 grep -q "msg=attached port=c1p" "$LGLOG"
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
	for ns in $NS_C1 $NS_C2 $NS_SRV $NS_RLY $NS_BR; do
		ns_kill "$ns"
		ip netns del "$ns" 2>/dev/null
	done
	"$LG" reset --pin-dir "$PIN" >/dev/null 2>&1
	rm -f /var/lib/dhcpcd/"$IF".* /run/dhcpcd/"$IF"-* "$LIBVIRT_STATUS"
	if [ "$failures" -ne 0 ] || [ "$rc" -ne 0 ]; then
		for f in "$TMP"/leaseguard.*.log; do echo; echo "--- $(basename "$f")"; cat "$f"; done
		for f in server relay client; do
			[ -e "$TMP/$f.log" ] && { echo "--- $f log"; tail -n 40 "$TMP/$f.log"; }
		done
		if [ -n "${LOGDIR:-}" ]; then
			mkdir -p "$LOGDIR" && cp -r "$TMP" "$LOGDIR/$SERVER${RELAY:+-relay}-$CLIENT"
		fi
	fi
	if [ -n "${KEEP:-}" ]; then echo "kept $TMP"; else rm -rf "$TMP"; fi
}

[ "$(id -u)" -eq 0 ] || { echo "interop.sh needs root"; exit 77; }
[ -x "$LG" ] || { echo "interop.sh: no leaseguard binary at $LG"; exit 2; }
need ip nsenter ping
case $SERVER in
dnsmasq) need dnsmasq ;;
libvirt) need dnsmasq; [ -x /usr/lib/libvirt/libvirt_leaseshelper ] ||
		skip_run "needs /usr/lib/libvirt/libvirt_leaseshelper (libvirt-daemon)" ;;
kea)     need kea-dhcp4 ;;
isc)     need dhcpd ;;
esac
case $CLIENT in
udhcpc)  need busybox ;;
*)       need "$CLIENT" ;;
esac
[ -n "$RELAY" ] && need dhcrelay
trap cleanup EXIT

# --- topology -------------------------------------------------------------------

log "setting up $NAME"
for ns in $NS_BR $NS_SRV $NS_C1 $NS_C2 ${RELAY:+$NS_RLY}; do
	ip netns add "$ns"
	ip -n "$ns" link set lo up
done
ip -n "$NS_BR" link add br0 type bridge
ip -n "$NS_BR" link set br0 up

# port PORT NS IFNAME MAC: veth pair, PORT on the bridge and IFNAME in NS.
port() {
	ip -n "$NS_BR" link add "$1" type veth peer name "$3" netns "$2"
	ip -n "$2" link set "$3" address "$4" up
	ip -n "$NS_BR" link set "$1" master br0 up
}

if [ -n "$RELAY" ]; then
	port up0 "$NS_RLY" eth0 "$MAC_UP"
	ip -n "$NS_RLY" addr add "$GW/24" dev eth0
	ip -n "$NS_RLY" link add eth1 type veth peer name "$IF" netns "$NS_SRV"
	ip -n "$NS_RLY" link set eth1 up
	ip -n "$NS_RLY" addr add 10.98.0.2/24 dev eth1
	ip -n "$NS_SRV" link set "$IF" up
	ip -n "$NS_SRV" addr add "$SRV_IP/24" dev "$IF"
	ip -n "$NS_SRV" route add 10.99.0.0/24 via 10.98.0.2
	in_ns "$NS_RLY" sysctl -qw net.ipv4.ip_forward=1
else
	port up0 "$NS_SRV" "$IF" "$MAC_UP"
	ip -n "$NS_SRV" addr add "$SRV_IP/24" dev "$IF"
fi
port c1p "$NS_C1" "$IF" "$MAC_C1"
port c2p "$NS_C2" "$IF" "$MAC_C2"
ip -n "$NS_C2" addr add 10.99.0.201/24 dev "$IF"

start_server || { bad "$SERVER started"; exit 1; }
ok "$SERVER started"
if [ -n "$RELAY" ]; then
	ip netns exec "$NS_RLY" dhcrelay -4 -d -id eth0 -iu eth1 "$SRV_IP" >"$TMP/relay.log" 2>&1 &
	if wait_until 10 grep -q "Sending on" "$TMP/relay.log"; then ok "dhcrelay started"
	else bad "dhcrelay started"; exit 1; fi
fi
write_client_config
start_leaseguard || { bad "leaseguard started"; exit 1; }
ok "leaseguard started"

# --- lease ----------------------------------------------------------------------

log "lease"
if client_start; then
	C1_IP=$(client_ip)
	ok "$CLIENT got a lease from $SERVER ($C1_IP)"
else
	bad "$CLIENT got a lease from $SERVER"; exit 1
fi
check "binding listed for c1p" has_binding "^c1p +0 +$MAC_C1 +$C1_IP +dhcp +in "
check "bind event logged" grep -q "msg=bind port=c1p vlan=0 mac=$MAC_C1 ip=$C1_IP lease=${LEASE_SECS}s" "$LGLOG"
check "c1 reaches $GW from its lease" ping_from "$NS_C1"
check_not "c2 without a lease cannot" ping_from "$NS_C2" "" 1

# Use an address that was not handed out; a static neighbor entry gets the
# packet past ARP inspection to the IPv4 check.
before=$(counter ip_mismatch)
ip -n "$NS_C1" neigh replace "$GW" lladdr "$MAC_UP" dev "$IF" nud permanent
ip -n "$NS_C1" addr add 10.99.0.200/24 dev "$IF"
check_not "c1 cannot use an address it was not given" ping_from "$NS_C1" 10.99.0.200 1
grew() { [ "$(counter ip_mismatch)" -gt "$before" ]; }
check "counted as ip_mismatch" grew
ip -n "$NS_C1" addr del 10.99.0.200/24 dev "$IF"
ip -n "$NS_C1" neigh del "$GW" dev "$IF"

# --- renewal --------------------------------------------------------------------

log "renewal"
n=$(binds "$C1_IP")
client_renew
renewed() { [ "$(binds "$C1_IP")" -gt "$n" ]; }
check "renewal ACK refreshes the binding" wait_until 20 renewed
check "c1 keeps its address" test "$(client_ip)" = "$C1_IP"
check "c1 still reaches $GW" ping_from "$NS_C1"

# --- release --------------------------------------------------------------------

log "release"
client_release
check "unbind event for the release" wait_until 5 grep -q \
	"msg=unbind port=c1p vlan=0 mac=$MAC_C1 ip=$C1_IP reason=release" "$LGLOG"
check_not "no binding left" has_binding "^c1p "
ip -n "$NS_C1" addr flush dev "$IF" scope global
ip -n "$NS_C1" addr add "$C1_IP/24" dev "$IF"
check_not "released address can no longer be used" ping_from "$NS_C1" "" 1
ip -n "$NS_C1" addr flush dev "$IF" scope global

# --- import ---------------------------------------------------------------------

log "import from the $SERVER lease file"
stop_leaseguard
lg reset >/dev/null
# The client gets its lease while nothing watches, then stops without a
# release, as if leaseguard were installed after the VM booted.
if client_start; then
	C1_IP=$(client_ip)
	ok "$CLIENT got a lease without leaseguard ($C1_IP)"
else
	bad "$CLIENT got a lease without leaseguard"; exit 1
fi
ns_kill "$NS_C1"
CLIENT_PID=
start_leaseguard --leases "$LEASES" || { bad "leaseguard restarted"; exit 1; }
check "lease file read" grep -q "msg=\"importing leases\" format=${LEASES%%:*} path=${LEASES#*:} leases=[1-9]" "$LGLOG"
check "c1 gets in once its lease is imported" wait_until 10 ping_from "$NS_C1" "" 1
check "import logged" grep -q "msg=import port=c1p vlan=0 mac=$MAC_C1 ip=$C1_IP expires=in " "$LGLOG"
check "binding listed as imported" has_binding "^c1p +0 +$MAC_C1 +$C1_IP +import +in "
check_not "c2 is still dropped" ping_from "$NS_C2" "" 1

# --- summary --------------------------------------------------------------------

stop_leaseguard
echo
echo "$NAME: $checks checks, $failures failures"
[ "$failures" -eq 0 ]
