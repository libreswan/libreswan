/testing/guestbin/swan-prep --nokeys
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
# conns added with auto=add in config file
sleep 5
ipsec status | grep west
echo "initdone"
