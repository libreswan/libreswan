/testing/guestbin/swan-prep --x509 --x509name east
ip route del 192.0.2.0/24
ifconfig eth0:1 192.0.2.254/24
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east-any
echo initdone
