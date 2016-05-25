/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east-port3
ipsec auto --add west-east-pass
ipsec auto --add west-east-pass2
nc -l 3 &
ipsec auto --route west-east-pass
ipsec auto --route west-east-pass2
echo "initdone"
