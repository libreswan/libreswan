../../guestbin/swan-prep --x509

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair suppress_retransmits
ipsec whack --impair revival

ipsec add road-east
ipsec add road-narrows-east
