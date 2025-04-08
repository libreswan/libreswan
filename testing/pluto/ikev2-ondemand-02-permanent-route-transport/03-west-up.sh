# check policy installed / uninstalled
ipsec route initiator
ipsec _kernel policy
ipsec unroute initiator
ipsec _kernel policy

# put trap back
ipsec route initiator
ipsec _kernel policy

# one ping to trigger IKE
../../guestbin/ping-once.sh --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match initiator -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus

# wait for larval state to clear; hack
../../guestbin/wait-for.sh --no-match 0x00000000 ipsec _kernel state

# real policy installed
ipsec _kernel policy
ipsec _kernel state
