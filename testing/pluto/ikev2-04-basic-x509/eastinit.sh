/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --add distraction
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"
