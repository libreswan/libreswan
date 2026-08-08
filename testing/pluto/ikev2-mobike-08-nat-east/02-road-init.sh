/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/road.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec add road
