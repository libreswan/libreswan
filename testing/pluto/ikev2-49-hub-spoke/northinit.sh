/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-westnet-ipv4-psk
ipsec auto --up northnet-westnet-ipv4-psk
ipsec auto --status
ipsec whack --impair suppress-retransmits
echo "initdone"
