# DROP

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair v2_proposal_integ:drop-none
ipsec up integ # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# ALLOW

ipsec whack --impair v2_proposal_integ:allow-none
ipsec whack --rekey-ike   --name integ # sanitize-retransmits
ipsec whack --rekey-child --name integ # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# DROP

ipsec whack --impair v2_proposal_integ:drop-none
ipsec whack --rekey-ike   --name integ # sanitize-retransmits
ipsec whack --rekey-child --name integ # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

ipsec stop
