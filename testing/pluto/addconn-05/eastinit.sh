/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec addconn --verbose east
echo "initdone"
