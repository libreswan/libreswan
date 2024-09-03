/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2a
ipsec auto --add westnet-eastnet-ikev2b
echo "initdone"
