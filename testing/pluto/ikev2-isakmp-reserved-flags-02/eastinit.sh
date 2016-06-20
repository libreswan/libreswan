/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-send-bogus-isakmp-flag
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
