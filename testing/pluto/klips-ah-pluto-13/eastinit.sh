/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ah-sha1-pfs
ipsec auto --status
echo "initdone"
