/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add road-east
ipsec whack --impair revival
echo initdone
