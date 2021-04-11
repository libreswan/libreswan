/testing/guestbin/swan-prep --userland strongswan
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.1.2.45 192.1.2.23
../../guestbin/strongswan-start.sh
echo "initdone"
