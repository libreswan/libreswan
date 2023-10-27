# ALLOW

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair v2-proposal-integ:allow-none
ipsec up integ
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# DROP

ipsec whack --impair v2-proposal-integ:drop-none
ipsec whack --rekey-ike   --name integ
ipsec whack --rekey-child --name integ
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# ALLOW

ipsec whack --impair v2-proposal-integ:allow-none
ipsec whack --rekey-ike   --name integ
ipsec whack --rekey-child --name integ
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

ipsec stop
