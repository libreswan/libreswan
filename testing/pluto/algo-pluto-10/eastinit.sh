setenforce 0
/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-aes256
ipsec auto --status |grep westnet-eastnet-aes256
echo "initdone"
