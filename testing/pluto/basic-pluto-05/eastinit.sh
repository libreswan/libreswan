/testing/guestbin/swan-prep
ipsec _stackmanager start 
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nonat
: ==== cut ====
ipsec auto --status
: ==== tuc ====
echo "initdone"
