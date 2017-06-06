/testing/guestbin/swan-prep --userland strongswan
# confirm that the network is alive
#../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
service strongswan start
sleep 3
echo "initdone"
