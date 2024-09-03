/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair replay_encrypted
ipsec whack --impair corrupt_encrypted
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
