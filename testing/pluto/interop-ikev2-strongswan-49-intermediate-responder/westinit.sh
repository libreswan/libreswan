/testing/guestbin/swan-prep --nokeys

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add intermediate-fragmentation-no
ipsec add intermediate-fragmentation-yes

echo "initdone"
