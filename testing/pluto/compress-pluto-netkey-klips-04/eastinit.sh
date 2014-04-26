: ==== start ====
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-compress
ipsec auto --status
ip xfrm policy
echo "initdone"
