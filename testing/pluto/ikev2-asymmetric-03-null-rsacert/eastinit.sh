/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
ipsec status
echo "initdone"
