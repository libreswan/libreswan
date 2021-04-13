/testing/guestbin/swan-prep --userland strongswan
# confirm that the network is alive
#../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
../../guestbin/strongswan-start.sh
echo "initdone"
