/testing/guestbin/swan-prep --x509
ipsec certutil -D -n east
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec add road
