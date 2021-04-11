/testing/guestbin/swan-prep --x509
# confirm that the network is alive
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add rw
echo "initdone"
