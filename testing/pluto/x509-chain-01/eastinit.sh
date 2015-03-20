/testing/guestbin/swan-prep --x509 --certchain
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509-chain
echo "initdone"
