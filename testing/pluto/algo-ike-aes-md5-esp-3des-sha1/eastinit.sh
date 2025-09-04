/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east-ikev1
ipsec add east-ikev2
echo "initdone"
