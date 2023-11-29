/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
echo "Leave ping running continuously in the background "
../../guestbin/ping-once.sh --up -I 192.0.2.254 192.0.1.254 2>&1 > /dev/null &
echo "initdone"
