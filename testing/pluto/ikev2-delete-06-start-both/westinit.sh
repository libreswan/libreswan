/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
#ipsec auto --add west-east-auto
echo "initdone"
