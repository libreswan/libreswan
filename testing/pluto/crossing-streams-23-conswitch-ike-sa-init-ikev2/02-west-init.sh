/testing/guestbin/swan-prep --nokey
ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair suppress_retransmits

# note order
ipsec add a
ipsec add b
