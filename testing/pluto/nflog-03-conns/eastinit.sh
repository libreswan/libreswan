/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-nflog
ipsec auto --add west-east-nflog
echo "initdone"
