/testing/guestbin/swan-prep --hostkey

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-compress
ipsec status | grep westnet-eastnet-compress
echo "initdone"
