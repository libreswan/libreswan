/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add labeled
runcon -t netutils_t ipsec getpeercon_server 4300 &
echo "initdone"
