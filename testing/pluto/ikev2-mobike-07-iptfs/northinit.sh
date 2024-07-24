/testing/guestbin/swan-prep
# second address on north 193.1.3.22
# add 193.1.3.22 before starting pluto. otherwise pluto may not listen bug
ip addr show dev eth1 | grep 192.1.3.22 || ip addr add 192.1.3.22/24 dev eth1
# add .33 for re-run
ip addr show dev eth1 | grep 192.1.3.33 || ip addr add 192.1.3.33/24 dev eth1
# add gw, it could have been deleted due address changes or could be diffrent on namespaces
ip route replace 192.1.2.0/24 via 192.1.3.254 src 192.1.3.33
# routes and addresses setup for the test
ipsec start
../../guestbin/wait-until-pluto-started
echo "initdone"
