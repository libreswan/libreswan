/testing/guestbin/swan-prep --userland strongswan
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.1.2.45 192.1.2.23
strongswan start
echo "initdone"
