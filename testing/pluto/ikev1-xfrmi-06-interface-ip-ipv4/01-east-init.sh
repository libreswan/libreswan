../../guestbin/ip.sh route get to 192.0.1.254 | grep eth1 && ip route del 192.0.1.0/24 via 192.1.2.45 dev eth1
../../guestbin/ip.sh route get to 192.0.3.254 | grep eth1 && ip route del 192.0.3.0/24 via 192.1.2.254 dev eth1
/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
echo "initdone"
