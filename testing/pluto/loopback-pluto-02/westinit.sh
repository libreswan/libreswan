/testing/guestbin/swan-prep
# confirm that the network is alive
ping -n -c 4 127.0.0.1
# make sure that clear text does not get through
iptables -A INPUT -i lo -p icmp  -j LOGDROP
# confirm with a ping 
ping -n -c 4 127.0.0.1
ipsec _stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add loopback-02-westleft
ipsec auto --status
echo "initdone"
