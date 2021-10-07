ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east-x509-ipv4
ipsec auto --up road-east-x509-ipv4
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec whack --trafficstatus
