/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/road.p12
/testing/x509/import.sh real/mainca/east.end.cert
/testing/x509/import.sh real/mainca/north.end.cert

ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/block-non-ipsec.sh
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
ipsec add road-east

echo initdone
