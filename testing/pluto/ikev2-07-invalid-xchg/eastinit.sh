/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair bad_ike_auth_xchg
ipsec add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
