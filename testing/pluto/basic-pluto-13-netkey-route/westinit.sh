/testing/guestbin/swan-prep
# confirm that the network is alive
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
sleep 4 # wait for addconn thread
ipsec auto --status | grep westnet-eastnet-route
echo "initdone"
