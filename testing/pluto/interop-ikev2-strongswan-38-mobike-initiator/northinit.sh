/testing/guestbin/swan-prep --userland strongswan
# delete the address .34 before re-run. otherwise strongswan may choose .34
../../guestbin/ip.sh address show dev eth1 | grep 192.1.3.34 && ../../guestbin/ip.sh address del 192.1.3.34/24 dev eth1
# add .33 in case re-run
../../guestbin/ip.sh address show dev eth1 | grep 192.1.3.33 || ../../guestbin/ip.sh address add 192.1.3.33/24 dev eth1
# add default gw, it could have been deleted due address changes
../../guestbin/ip.sh route | grep default || ip route add default via 192.1.3.254
../../guestbin/ip.sh address add 192.1.3.34/24 dev eth1
../../guestbin/strongswan-start.sh
echo "initdone"
