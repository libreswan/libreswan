/testing/guestbin/swan-prep --nokeys

ipsec start
../../guestbin/wait-until-pluto-started

ipsec add westnet-eastnet-ikev2a
ipsec add westnet-eastnet-ikev2b

echo "initdone"
