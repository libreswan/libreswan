/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-port666
ipsec auto --add westnet-eastnet-port667
echo "initdone"
