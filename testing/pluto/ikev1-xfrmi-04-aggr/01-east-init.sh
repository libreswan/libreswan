../../guestbin/ip.sh route get to 192.0.1.254 | grep eth1 && ip route del 192.0.1.0/24 via 192.1.2.45 dev eth1 2>/dev/null
../../guestbin/ip.sh route get to 192.0.3.254 | grep eth1 && ip route del 192.0.3.0/24 via 192.1.2.254 dev eth1 2>/dev/null
#new subnet
../../guestbin/ip.sh address show dev eth0 | grep 192.0.22.254 || ../../guestbin/ip.sh address add 192.0.22.254/24 dev eth0
/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnet
ipsec auto --add westnet-eastnet
echo "initdone"
