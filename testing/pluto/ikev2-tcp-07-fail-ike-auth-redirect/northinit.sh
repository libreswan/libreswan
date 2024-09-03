/testing/guestbin/swan-prep --nokeys
ifconfig eth0:1 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add north
echo "initdone"
