ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-send-bogus-dcookie
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
