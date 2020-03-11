/testing/guestbin/swan-prep --userland strongswan
#../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
../../pluto/bin/strongswan-start.sh
ip link add ipsec2 type xfrm if_id 2 dev eth0
swanctl  --load-conns
echo "initdone"
