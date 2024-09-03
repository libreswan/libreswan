/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec auto --status | grep westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
ipsec whack --impair revival
