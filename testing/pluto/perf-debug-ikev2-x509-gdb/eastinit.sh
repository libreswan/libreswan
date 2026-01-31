/testing/guestbin/swan-prep --x509

sh ./gdb.sh & sleep 1
../../guestbin/wait-until-pluto-started

ipsec add westnet-eastnet-ikev2
echo "initdone"
