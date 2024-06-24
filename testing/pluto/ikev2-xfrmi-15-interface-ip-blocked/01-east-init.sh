/testing/guestbin/swan-prep --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet4-eastnet4
ipsec auto --add westnet6-eastnet6
echo "initdone"
