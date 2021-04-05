/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add modecfg-road-eastnet-psk
# confirm we have stock resolv.conf
cat /etc/resolv.conf
echo initdone
