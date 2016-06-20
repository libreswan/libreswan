../../guestbin/swan-prep
ipsec setup start
../../pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-propnum
echo "initdone"
