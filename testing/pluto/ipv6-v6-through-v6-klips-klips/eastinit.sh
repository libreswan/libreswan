/testing/guestbin/swan-prep --46
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-6in6
ipsec auto --status
echo "initdone"
