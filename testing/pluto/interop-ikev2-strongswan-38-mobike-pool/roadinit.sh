/testing/guestbin/swan-prep --userland strongswan
# delete the address 33.222 before re-run. otherwise strongswan may choose 33.222
ip addr show dev eth0 | grep 192.1.33.222 && ip addr del 192.1.33.222/24 dev eth0
# add .209 in case re-run
ip addr show dev eth0 | grep 192.1.3.209 || ip addr add 192.1.3.209/24 dev eth0
ip addr add 192.1.33.222/24 dev eth0
# add default gw, it could have been deleted due address changes
../../guestbin/route.sh | grep default || ip route add default via 192.1.3.254
../../guestbin/strongswan-start.sh
echo "initdone"
