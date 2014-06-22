/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add labeled
getpeerconn 4300 &
echo "initdone"
