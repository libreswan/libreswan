/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add replay
ipsec auto --status | grep replay_window
echo "initdone"
