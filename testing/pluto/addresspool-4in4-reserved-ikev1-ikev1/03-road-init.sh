/testing/guestbin/swan-prep --x509

ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/block-non-ipsec.sh
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
ipsec add road-east

echo initdone
