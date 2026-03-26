/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec status |grep "ikev1-policy"
# should fail
ipsec auto --add ikev1
# should work but unused
ipsec auto --add ikev2
echo "initdone"
