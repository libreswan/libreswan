/testing/guestbin/swan-prep --x509
ipsec _stackmanager start 
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east-x509-pluto-02
ipsec auto --status
ipsec auto --listall
echo "initdone"
