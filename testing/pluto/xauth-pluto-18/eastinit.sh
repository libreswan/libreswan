/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add modecfg-road-eastnet-psk
echo initdone
