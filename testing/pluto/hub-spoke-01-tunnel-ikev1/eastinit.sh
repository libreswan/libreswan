/testing/guestbin/swan-prep --nokeys

ipsec start
../../guestbin/wait-until-pluto-started

ipsec add westnet-northnet-ipv4-psk
ipsec add northnet-westnet-ipv4-psk

echo "initdone"
