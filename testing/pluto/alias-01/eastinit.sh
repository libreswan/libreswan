/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# connalias
ipsec auto --add franklin
echo "initdone"
