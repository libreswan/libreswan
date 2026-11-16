/testing/guestbin/swan-prep --nokeys

ipsec start
../../guestbin/wait-until-pluto-started

ipsec add northnet-westnet-ipv4-psk
ipsec up northnet-westnet-ipv4-psk # sanitize-retransmits
../../guestbin/wait-for.sh --match '#2: IPsec SA established tunnel mode' -- cat OUTPUT/east.pluto.log

echo "initdone"
