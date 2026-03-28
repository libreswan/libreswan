/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/block-non-ipsec.sh
ipsec add north-east
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name north-east --initiate # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.0.2.254
ipsec trafficstatus
echo initdone
