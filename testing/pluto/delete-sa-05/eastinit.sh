/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
# connections are loaded and initiated via auto=start
echo "initdone"
