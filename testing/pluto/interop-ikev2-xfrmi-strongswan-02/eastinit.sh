/testing/guestbin/swan-prep --userland strongswan
#../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
../../guestbin/strongswan-start.sh
../../guestbin/ip.sh link set down dev ipsec0 2> /dev/null > /dev/null
../../guestbin/ip.sh link del ipsec0 2> /dev/null > /dev/null
#shouldn't charon clean up these two rules ??
ip rule del pref 220 2> /dev/null > /dev/null
../../guestbin/ip.sh route del 192.1.2.0/24 dev eth0 table 220 2> /dev/null > /dev/null
../../guestbin/ip.sh link add ipsec0 type xfrm if_id 2 dev eth0
# KVM and namespace has this route
../../guestbin/ip.sh route del 192.0.1.0/24
../../guestbin/ip.sh link set up dev ipsec0
../../guestbin/ip.sh route add 192.0.1.0/24 dev ipsec0
swanctl  --load-conns
echo "initdone"
