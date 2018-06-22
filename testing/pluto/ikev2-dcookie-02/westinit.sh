/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair send-bogus-dcookie
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
