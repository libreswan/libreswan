/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add replay
ipsec auto --status | grep replay_window
echo "initdone"
