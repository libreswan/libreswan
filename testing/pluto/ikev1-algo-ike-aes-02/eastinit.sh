/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-3des
ipsec auto --status |grep westnet-eastnet-3des
echo "initdone"
