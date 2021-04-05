/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-esp-null
ipsec auto --status | grep westnet-eastnet-esp-null
echo "initdone"
