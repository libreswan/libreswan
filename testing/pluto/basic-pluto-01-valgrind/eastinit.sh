/testing/guestbin/swan-prep
ipsec _stackmanager start 
valgrind /usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf &
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec auto --status
echo "initdone"
