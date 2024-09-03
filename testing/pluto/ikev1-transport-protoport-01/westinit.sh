/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ipv4-psk-ikev2-transport
ipsec whack --impair suppress_retransmits
echo "initdone"
