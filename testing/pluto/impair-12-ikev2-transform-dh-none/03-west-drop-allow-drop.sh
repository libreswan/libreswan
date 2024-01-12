# DROP

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair v2_proposal_dh:drop-none
ipsec up dh
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# ALLOW

ipsec whack --impair v2_proposal_dh:allow-none
ipsec whack --rekey-ike   --name dh
ipsec whack --rekey-child --name dh
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# DROP

ipsec whack --impair v2_proposal_dh:drop-none
ipsec whack --rekey-ike   --name dh
ipsec whack --rekey-child --name dh
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

ipsec stop
