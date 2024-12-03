# resume after two key rollovers - ticket expired
ipsec up west-east
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec whack --suspend --name west-east
