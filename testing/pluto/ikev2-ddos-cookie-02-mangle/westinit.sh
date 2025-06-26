/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair ddos_cookie:mangle
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
ipsec add westnet-eastnet-ikev2
echo "initdone"
