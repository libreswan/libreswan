/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
# ipsec add any-east
ipsec add north-any-east
ipsec add road-any-east
echo initdone
