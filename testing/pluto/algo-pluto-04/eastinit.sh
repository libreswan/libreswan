/testing/guestbin/swan-prep
ipsec _stackmanager start 
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-esp-sha1-pfs
ipsec auto --add westnet-eastnet-esp-md5-pfs
ipsec auto --status
echo "initdone"
