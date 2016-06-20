../../guestbin/swan-prep
ipsec start
../../pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-propnum
echo "initdone"
