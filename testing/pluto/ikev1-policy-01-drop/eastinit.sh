/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec status |grep "ikev1-policy"
# should fail
ipsec auto --add ikev1
# should work but unused
ipsec auto --add ikev2
echo "initdone"
