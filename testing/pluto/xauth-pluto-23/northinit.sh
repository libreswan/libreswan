/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/north.p12
/testing/x509/import.sh real/mainca/east.end.cert
/testing/x509/import.sh real/mainca/road.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add north-east
ipsec whack --xauthname 'xnorth' --xauthpass 'use1pass' --name north-east --initiate # sanitize-retransmits
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
echo initdone
