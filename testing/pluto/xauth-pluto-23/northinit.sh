/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add north-east
ipsec whack --xauthname 'xnorth' --xauthpass 'use1pass' --name north-east --initiate # sanitize-retransmits
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
echo initdone
