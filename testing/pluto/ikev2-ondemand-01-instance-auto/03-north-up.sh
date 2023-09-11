# check policy installed
../../guestbin/ipsec-kernel-policy.sh

# one ping to trigger IKE
../../guestbin/ping-once.sh --forget -I 192.0.3.254 192.0.2.254
../../guestbin/wait-for.sh --match north -- ipsec whack --trafficstatus
# success
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus

# wait for larval state to clear; hack
../../guestbin/wait-for.sh --no-match 0x00000000 ../../guestbin/ipsec-kernel-state.sh

../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ipsec-kernel-state.sh

ipsec auto --down north

#everything but trap cleared
../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ipsec-kernel-state.sh
