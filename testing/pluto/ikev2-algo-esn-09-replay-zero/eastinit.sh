/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
ipsec auto --status | grep replay_window
ipsec auto --status | grep -E -i ESN
echo "initdone"
