/testing/guestbin/swan-prep

ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/block-non-ipsec.sh
ipsec add road-east

echo initdone
