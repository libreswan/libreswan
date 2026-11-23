/testing/guestbin/swan-prep --nokeys
../../guestbin/block-non-ipsec.sh
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-initial
ipsec add west-additional
echo initdone
