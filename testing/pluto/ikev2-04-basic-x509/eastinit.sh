/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
ipsec add distraction
ipsec connectionstatus westnet-eastnet-ikev2
echo "initdone"
