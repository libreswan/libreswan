/testing/guestbin/swan-prep --userland strongswan
# confirm that the network is alive
#../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
strongswan starter --debug-all
echo "initdone"
