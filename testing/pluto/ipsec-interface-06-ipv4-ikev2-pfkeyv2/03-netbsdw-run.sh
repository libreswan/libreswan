ifconfig ipsec1
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

ipsec up west

../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

../../guestbin/tcpdump.sh --start -i ipsec1 &

ifconfig ipsec1
../../guestbin/ping-once.sh --up -I 192.0.1.251 192.0.2.254

../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

../../guestbin/tcpdump.sh --stop -i ipsec1

ipsec down west
ipsec delete west
