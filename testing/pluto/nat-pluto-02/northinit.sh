/testing/guestbin/swan-prep
ping -c 4 -n 192.0.3.254
ipsec _stackmanager start 
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east-port19
ipsec auto --add north-east-pass
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt
ipsec auto --status
echo "initdone"
