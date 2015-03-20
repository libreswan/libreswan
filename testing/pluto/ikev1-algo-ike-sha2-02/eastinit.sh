setenforce 0
/testing/guestbin/swan-prep
#ipsec _stackmanager start 
#/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-sha2
ipsec auto --status
echo "initdone"
