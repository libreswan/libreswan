/testing/guestbin/swan-prep --x509 --46
dig +short east46.testing.libreswan.org A
dig +short east46.testing.libreswan.org AAAA
ip -4 route
ip -6 route
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add road
echo "initdone"
