/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec addconn --verbose west
ipsec addconn --verbose west-bogus
echo "initdone"
