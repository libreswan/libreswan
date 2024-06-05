/testing/guestbin/swan-prep
../../guestbin/ip.sh route get to 192.0.2.254 | grep eth1 && ip route del 192.0.2.0/24 via 192.1.3.254 dev eth1
../../guestbin/ip.sh route get to 192.0.1.254 | grep eth1 && ip route del 192.0.1.0/24 via 192.1.3.254 dev eth1
ip addr show dev eth0 | grep 192.0.33.254 || ip addr add 192.0.33.254/24 dev eth0
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-west
ipsec auto --add north-east
echo "initdone"

