# check policy installed / uninstalled
ipsec route initiator
../../guestbin/ipsec-kernel-policy.sh
ipsec unroute initiator
../../guestbin/ipsec-kernel-policy.sh

# put trap back
ipsec route initiator
../../guestbin/ipsec-kernel-policy.sh

# one ping to trigger IKE
../../guestbin/ping-once.sh --forget -I 192.0.3.254 192.0.2.254
../../guestbin/wait-for.sh --match initiator -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus

# real policy installed
../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ipsec-kernel-state.sh
