../../guestbin/ip.sh address add 192.1.3.34/24 dev eth1 2>/dev/null
../../guestbin/ip.sh address add 192.1.3.35/24 dev eth1 2>/dev/null
../../guestbin/ip.sh address add 192.1.3.36/24 dev eth1 2>/dev/null
/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east-21
ipsec auto --add north-east-22
ipsec auto --add north-east-23
ipsec auto --add north-east-24
echo "initdone"
