/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack suppress-retransmits # failure is an option
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
