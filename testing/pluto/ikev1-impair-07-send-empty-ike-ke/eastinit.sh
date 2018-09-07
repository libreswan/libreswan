/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair send-empty-ke-payload
ipsec auto --add westnet-eastnet-ipv4-psk-slow
echo "initdone"
