/testing/guestbin/swan-prep --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet4-eastnet4
ipsec add westnet6-eastnet6
echo "initdone"
