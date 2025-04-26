# resume after one key rollover; since east has old key things work
ipsec up west-east
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec whack --suspend --name west-east
