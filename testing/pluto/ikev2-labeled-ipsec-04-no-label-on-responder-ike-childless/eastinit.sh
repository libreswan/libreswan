/testing/guestbin/swan-prep --hostkeys
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add labeled
echo "initdone"
