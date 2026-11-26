/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add rekey
ipsec add rekey1
ipsec add rekey2
echo "initdone"
