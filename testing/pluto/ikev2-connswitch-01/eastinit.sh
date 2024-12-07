/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/ipsec-add.sh distraction westnet-eastnet
echo "initdone"
