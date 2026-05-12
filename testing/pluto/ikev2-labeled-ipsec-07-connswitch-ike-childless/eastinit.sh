/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
# note order; it seems to matter (but shouldn't)
ipsec add west-to-east
ipsec add distraction
