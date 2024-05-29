/testing/guestbin/swan-prep --x509
../../guestbin/route.sh del 192.0.1.0/24
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east-any
echo initdone
