/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
# connection is loaded and initiated via auto=start
echo "initdone"
