/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec auto --add distraction
ipsec auto --status | grep westnet-eastnet
echo "initdone"
