ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
