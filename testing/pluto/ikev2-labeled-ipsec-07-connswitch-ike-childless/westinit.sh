/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add distraction
ipsec auto --add west-to-east
