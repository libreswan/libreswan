/testing/guestbin/swan-prep --46 --nokeys
/testing/x509/import.sh real/mainca/road.p12
/testing/x509/import.sh real/mainca/east.end.cert
dig +short east46.testing.libreswan.org A
dig +short east46.testing.libreswan.org AAAA
../../guestbin/ip-route.sh -4
../../guestbin/ip-route.sh -6
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add road
echo "initdone"
