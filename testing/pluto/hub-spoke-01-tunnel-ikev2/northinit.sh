/testing/guestbin/swan-prep --nokeys

ipsec start
../../guestbin/wait-until-pluto-started

ipsec add northnet-westnet-ipv4-psk
ipsec up northnet-westnet-ipv4-psk # sanitize-retransmits

echo "initdone"
