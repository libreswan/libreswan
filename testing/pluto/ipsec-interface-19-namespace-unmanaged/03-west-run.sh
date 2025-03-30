#
# Existing ipsec-interface with address
#
# Neither the ipsec-interface nor the address are created by pluto, so
# pluto leaves both behind.

ipsec add westnet4-eastnet4

ipsec up westnet4-eastnet4

../../guestbin/ip.sh netns exec ns ../../guestbin/ping-once.sh --up -I 192.0.1.251 192.0.2.254
ipsec trafficstatus
ipsec _kernel state
ipsec _kernel policy

cat /proc/net/xfrm_stat

ipsec delete westnet4-eastnet4
