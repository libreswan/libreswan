/testing/guestbin/swan-prep --x509 --46
dig +short east46.testing.libreswan.org A
dig +short east46.testing.libreswan.org AAAA
../../guestbin/ip.sh -4 route
../../guestbin/ip.sh -6 route
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add road
echo "initdone"
