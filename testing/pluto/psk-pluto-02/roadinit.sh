/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add road-eastnet-psk
ipsec auto --status | grep road-eastnet-psk
echo "initdone"
