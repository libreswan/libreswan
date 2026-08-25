/testing/guestbin/swan-prep --nokeys
# confirm that the network is alive
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east-delete1
ipsec connectionstatus west-east
echo "initdone"
