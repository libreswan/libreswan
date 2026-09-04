/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec connectionstatus "ikev1-policy"
# should fail
ipsec add ikev1
# should work but unused
ipsec add ikev2
echo "initdone"
