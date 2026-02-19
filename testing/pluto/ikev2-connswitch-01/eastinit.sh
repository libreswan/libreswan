/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add distraction
ipsec add westnet-eastnet
echo "initdone"
