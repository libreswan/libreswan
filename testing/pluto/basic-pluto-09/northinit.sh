/testing/guestbin/swan-prep
ping -n -c 4 -I 192.0.3.254 192.0.2.254
ipsec _stackmanager start 
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nonat
: ==== cut ====
ipsec auto --status
: ==== tuc ====
echo "initdone"
