/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
: ==== cut ====
ipsec auto --status
: ==== tuc ====
echo "initdone"
