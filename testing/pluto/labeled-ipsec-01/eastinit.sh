/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add labeled
nc -vvv -l 192.0.2.254 4300 &
echo "initdone"
