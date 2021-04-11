/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet1
ipsec auto --add westnet-eastnet2
echo "initdone"
