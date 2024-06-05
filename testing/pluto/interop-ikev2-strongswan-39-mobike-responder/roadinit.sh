/testing/guestbin/swan-prep
# delete the address 33.222 before re-run. otherwise strongswan may choose 33.222
ip addr show dev eth0 | grep 192.1.33.222 && ip addr del 192.1.33.222/24 dev eth0
../../guestbin/ip.sh route show scope global | grep "192.1.33.254" && ip route del default via 192.1.33.254
# add .209 in case re-run
ip addr show dev eth0 | grep 192.1.3.209 || ip addr add 192.1.3.209/24 dev eth0
ip addr add 192.1.33.222/24 dev eth0
# add default gw, it could have been deleted due address changes
../../guestbin/ip.sh route | grep default || ip route add default via 192.1.3.254
# routes and address setup done
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-eastnet
echo "initdone"
