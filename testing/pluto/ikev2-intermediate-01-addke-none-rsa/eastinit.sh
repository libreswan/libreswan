/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add any-east
ipsec connectionstatus | grep ' policy: '
echo "initdone"
