/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add distraction
ipsec add west-to-east
