/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add northnet-westnet-ipv4-psk
ipsec auto --up northnet-westnet-ipv4-psk
ipsec auto --status
echo "initdone"
