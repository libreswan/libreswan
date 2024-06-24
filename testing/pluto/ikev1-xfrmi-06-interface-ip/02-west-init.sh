../../guestbin/ip.sh route get to 192.0.2.254 | grep 192.1.2.23 > /dev/null 2> /dev/null && ip route del 192.0.2.0/24 via 192.1.2.23 dev eth1 || true
/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet
echo "initdone"
