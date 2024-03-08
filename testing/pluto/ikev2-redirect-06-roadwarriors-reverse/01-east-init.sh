/testing/guestbin/swan-prep --x509
ip route del 192.0.1.0/24
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east-any
echo initdone
