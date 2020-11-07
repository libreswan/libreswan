/testing/guestbin/swan-prep
# Run the System Role generation for host "west" here.
./w-systemrole.sh
# test config for syntax errors
ipsec addconn --checkconfig --config /etc/ipsec.conf
# start for test
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# test secrets reading for early warning of syntax errors
ipsec secrets
echo "initdone"
