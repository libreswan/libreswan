/testing/guestbin/swan-prep --userland strongswan
../../guestbin/strongswan-start.sh
ip link set down dev ipsec2 2> /dev/null > /dev/null
ip link del ipsec2 2> /dev/null > /dev/null
ip rule del pref 220 2> /dev/null > /dev/null
../../guestbin/route.sh del 192.0.2.0/24
../../guestbin/route.sh del 192.1.2.0/24 dev eth0 table 220 2> /dev/null > /dev/null
ip link add ipsec2 type xfrm if_id 2 dev eth0
swanctl  --load-conns
echo "initdone"
