/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair bad_ike_auth_xchg
ipsec whack --impair suppress_retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
