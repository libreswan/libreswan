/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair add-unknown-v2-payload-to-sk:IKE_AUTH
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
