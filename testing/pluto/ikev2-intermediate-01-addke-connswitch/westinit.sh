/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.p12
/testing/x509/import.sh real/mainca/east.end.cert

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add psk
ipsec add rsa-west

ipsec whack --impair suppress_retransmits

echo "initdone"
