/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair add-unknown-payload-to-auth,unknown-payload-critical
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
