/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add rw-eastnet-pool-x509-ipv4
echo "initdone"
