/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair timeout_on_retransmit
ipsec add westnet-eastnet-ipv4-psk-ikev1
echo "initdone"
