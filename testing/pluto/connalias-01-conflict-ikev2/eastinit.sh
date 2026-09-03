/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
# connalias
ipsec add franklin
echo "initdone"
