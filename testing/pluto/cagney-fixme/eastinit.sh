/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ikev1
# should show both keys but doesn't
ipsec whack --listpubkeys
# rinse and repeat
ipsec auto --add ikev1
# now it will show ??
ipsec whack --listpubkeys
echo "initdone"
