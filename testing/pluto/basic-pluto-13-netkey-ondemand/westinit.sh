/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
sleep 4 # wait for addconn thread
ipsec auto --status | grep westnet-eastnet-route
echo "initdone"
