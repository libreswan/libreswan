/testing/guestbin/swan-prep
rm /etc/ipsec.d/*db
ipsec initnss > /dev/null 2> /dev/null
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
echo "initdone"
