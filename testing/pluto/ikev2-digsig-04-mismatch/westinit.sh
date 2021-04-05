/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec status | grep westnet-eastnet-ikev2 | grep policy: | grep -v modecfg
echo "initdone"
