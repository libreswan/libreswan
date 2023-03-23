# trigger ping, this will be lost
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus

# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23

# get assigned 10.0.10.1 so expect 10.0.10.1/32<->192.1.2.23/32 along
# with the ping 192.1.3.209/32->192.1.2.23/32 and the original trap
# 192.1.3.209/32->192.1.2.23/24.
../../guestbin/ipsec-kernel-policy.sh
ipsec whack --trafficstatus
ipsec whack --shuntstatus
