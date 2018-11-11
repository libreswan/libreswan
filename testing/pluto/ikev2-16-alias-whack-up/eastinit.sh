/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnets
ipsec auto --status | grep northnet-eastnets
ipsec whack --impair suppress-retransmits
echo "initdone"
