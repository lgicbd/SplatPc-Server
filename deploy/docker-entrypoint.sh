#!/bin/sh
set -eu

WG_IFACE="${WG_INTERFACE:-wg0}"
WG_IP="${WG_SERVER_IP:-10.66.0.1}"
WG_CIDR="${WG_SUBNET:-10.66.0.0/16}"
WG_PREFIX_LEN="${WG_CIDR#*/}"
WG_MTU_VAL="${WG_MTU:-1420}"

# Create WireGuard interface if not present (kernel WireGuard).
if ! ip link show "$WG_IFACE" >/dev/null 2>&1; then
    ip link add dev "$WG_IFACE" type wireguard
fi

ip addr replace "${WG_IP}/${WG_PREFIX_LEN}" dev "$WG_IFACE"
ip link set mtu "$WG_MTU_VAL" dev "$WG_IFACE"
ip link set up dev "$WG_IFACE"

exec /usr/local/bin/splatoon-nex "$@"
