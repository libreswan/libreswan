/testing/guestbin/swan-prep --nokeys
../../guestbin/ip.sh address add 192.0.21.254/24 dev eth0 2>/dev/null
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add north-east-gw
ipsec add north-east-sn
echo "initdone"
