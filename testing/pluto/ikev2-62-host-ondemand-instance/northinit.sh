/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
# ipsec auto --add north-east
echo "initdone"
