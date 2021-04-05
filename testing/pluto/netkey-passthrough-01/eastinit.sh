/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east-passthrough
ipsec auto --route west-east-passthrough
ipsec auto --add west-east
nc -4 -l 192.1.2.23 222 &
echo "initdone"
