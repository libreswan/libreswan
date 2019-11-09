/testing/guestbin/swan-prep --x509
ip route del 192.0.1.0/24
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add east-any
echo initdone
