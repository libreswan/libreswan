/testing/guestbin/swan-prep --46 --nokeys

/testing/x509/import.sh real/mainca/key4096.all.p12
/testing/x509/import.sh real/mainca/east.end.cert

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add v6-tunnel
ipsec whack --impair suppress_retransmits
echo "initdone"
