ipsec auto --up west-east
ipsec status | grep ticket
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec whack --trafficstatus

ipsec whack --suspend --name west-east

ipsec up west-east
ipsec status | grep ticket
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
