/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair add-unknown-v2-payload-to:IKE_AUTH
ipsec whack --impair unknown-v2-payload-critical
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
