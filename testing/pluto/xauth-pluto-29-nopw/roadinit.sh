/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add xauth-road-eastnet-psk
echo "initdone"
