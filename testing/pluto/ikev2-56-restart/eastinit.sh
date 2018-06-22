/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
echo "Leave ping running continuously in the background "
ping -n -I 192.0.2.254 192.0.1.254 2>&1 > /dev/null &
echo "initdone"
