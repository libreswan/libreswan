/testing/guestbin/swan-prep --nokeys
../../guestbin/ip.sh route del 192.0.1.0/24
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east
ipsec status |grep redirect
echo "initdone"
