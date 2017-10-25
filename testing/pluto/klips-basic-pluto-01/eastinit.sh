/testing/guestbin/swan-prep
setenforce 0
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec auto --status
echo "initdone"
