/testing/guestbin/swan-prep --x509 --46
dig +short east46.testing.libreswan.org A
dig +short east46.testing.libreswan.org AAAA
../../guestbin/route.sh -4
../../guestbin/route.sh -6
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add road
echo "initdone"
