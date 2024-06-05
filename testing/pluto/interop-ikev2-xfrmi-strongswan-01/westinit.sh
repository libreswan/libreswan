/testing/guestbin/swan-prep --userland strongswan
../../guestbin/strongswan-start.sh
../../guestbin/ip.sh link set down dev ipsec2 2> /dev/null > /dev/null
../../guestbin/ip.sh link del ipsec2 2> /dev/null > /dev/null
ip rule del pref 220 2> /dev/null > /dev/null
../../guestbin/ip.sh route del 192.0.2.0/24
../../guestbin/ip.sh route del 192.1.2.0/24 dev eth0 table 220 2> /dev/null > /dev/null
../../guestbin/ip.sh link add ipsec2 type xfrm if_id 2 dev eth0
swanctl  --load-conns
echo "initdone"
