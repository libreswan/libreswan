/testing/guestbin/swan-prep --x509
ipsec certutil  -D -n mainca
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509-nosend
ipsec auto --status | grep westnet-eastnet-x509-nosend
echo "initdone"
