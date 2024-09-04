/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet
ipsec status | grep westnet-eastnet
echo "initdone"
