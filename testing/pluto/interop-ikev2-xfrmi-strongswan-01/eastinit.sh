/testing/guestbin/swan-prep --userland strongswan
#../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
../../guestbin/strongswan-start.sh
ip link set down dev ipsec2 2> /dev/null > /dev/null
ip link del ipsec2 2> /dev/null > /dev/null
#shouldn't charon clean up these two rules ??
ip rule del pref 220 2> /dev/null > /dev/null
../../guestbin/route.sh del 192.1.2.0/24 dev eth0 table 220 2> /dev/null > /dev/null
ip link add ipsec2 type xfrm if_id 2 dev eth0
# KVM and namespace has this route
../../guestbin/route.sh del 192.0.1.0/24
ip link set up dev ipsec2
../../guestbin/route.sh add 192.0.1.0/24 dev ipsec2
swanctl  --load-conns
echo "initdone"
