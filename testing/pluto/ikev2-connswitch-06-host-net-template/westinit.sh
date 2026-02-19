/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2-b
ipsec whack --impair suppress_retransmits
echo "initdone"
