/testing/guestbin/swan-prep --46
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add rw-eastnet-ipv6
ipsec auto --status
echo "initdone"
