/testing/guestbin/swan-prep
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.254/32 -j LOGDROP
# confirm with a ping
ping -c 4 -n -I 192.0.3.254 192.0.2.254
ipsec _stackmanager start 
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet--eastnet-nonat
ipsec auto --status
echo "initdone"
