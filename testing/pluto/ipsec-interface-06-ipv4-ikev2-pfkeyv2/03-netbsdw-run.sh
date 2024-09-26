ifconfig ipsec1
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

ifconfig ipsec1 create
ifconfig ipsec1 tunnel 192.1.2.45 192.1.2.23
ifconfig ipsec1 inet 192.0.1.251/24 192.0.1.251
ifconfig ipsec1 up
ifconfig ipsec1
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
ifconfig ipsec1 destroy

ipsec up west

../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

../../guestbin/tcpdump.sh --start -i ipsec1

ifconfig ipsec1
../../guestbin/ping-once.sh --up -I 192.0.1.251 192.0.2.254
../../guestbin/ping-once.sh --up -I ipsec1 192.0.2.254

../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

../../guestbin/tcpdump.sh --stop -i ipsec1

# ipsec down west
# ipsec delete west
