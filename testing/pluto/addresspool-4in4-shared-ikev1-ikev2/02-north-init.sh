/testing/guestbin/swan-prep

ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/block-non-ipsec.sh
ipsec add ikev2-north-east

echo initdone
