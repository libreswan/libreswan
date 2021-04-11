/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair replay-encrypted
ipsec whack --impair corrupt-encrypted
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
