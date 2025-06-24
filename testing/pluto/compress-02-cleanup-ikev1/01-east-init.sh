/testing/guestbin/swan-prep --hostkey

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-compress
ipsec auto --status | grep westnet-eastnet-compress
echo "initdone"
