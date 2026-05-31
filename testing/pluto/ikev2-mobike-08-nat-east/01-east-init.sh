/testing/guestbin/swan-prep --x509
/testing/x509/import.sh real/mainca/east.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec add east
