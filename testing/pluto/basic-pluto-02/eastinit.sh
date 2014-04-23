/testing/guestbin/swan-prep
ipsec _stackmanager start 
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
# intentionally comment out this policy
# ipsec auto --add westnet-eastnet
ipsec auto --status
echo "initdone"
