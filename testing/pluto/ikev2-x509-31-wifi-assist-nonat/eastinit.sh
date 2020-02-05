/testing/guestbin/swan-prep --x509
# confirm that the network is alive
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add rw
echo "initdone"
