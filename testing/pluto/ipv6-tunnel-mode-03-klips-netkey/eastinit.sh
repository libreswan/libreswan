/testing/guestbin/swan-prep --6
ipsec _stackmanager start 
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add v6-tunnel
ipsec auto --status
echo "initdone"
