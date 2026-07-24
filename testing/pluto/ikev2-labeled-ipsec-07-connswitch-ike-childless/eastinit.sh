/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/west.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
# note order; it seems to matter (but shouldn't)
ipsec add west-to-east
ipsec add distraction
