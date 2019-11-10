/testing/guestbin/swan-prep
# confirm that the network is alive
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east-delete1
ipsec auto --status | grep west-east
echo "initdone"
