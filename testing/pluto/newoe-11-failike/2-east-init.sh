/testing/guestbin/swan-prep --nokeys
# no connections loaded
ipsec start
../../guestbin/wait-until-pluto-started
echo "initdone"
