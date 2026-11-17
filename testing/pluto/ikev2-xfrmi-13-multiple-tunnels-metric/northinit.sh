../../guestbin/ip.sh address add 192.1.3.33/24 dev eth1 2>/dev/null
/testing/guestbin/swan-prep --nokeys

ipsec start
../../guestbin/wait-until-pluto-started

ipsec add north-east-gw
ipsec add north-east-sn

echo "initdone"
