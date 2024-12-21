/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add any-east
echo initdone
