/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair ke_payload:omit
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
