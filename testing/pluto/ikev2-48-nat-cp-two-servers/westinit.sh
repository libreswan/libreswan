/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add rw-westnet-pool-x509-ipv4
echo "initdone"
