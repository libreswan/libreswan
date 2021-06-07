/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair omit-v2-ike-auth-child
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
