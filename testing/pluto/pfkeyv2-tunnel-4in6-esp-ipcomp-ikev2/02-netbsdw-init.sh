# note swan-prep does not yet support BSD
../../guestbin/netbsd-prep.sh

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add eastnet-westnet-ikev2
echo "initdone"
