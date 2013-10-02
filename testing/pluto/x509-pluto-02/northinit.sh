/testing/guestbin/swan-prep --x509
# make sure that clear text does not get through
iptables -A INPUT -i eth0 -s 192.0.2.0/24 -j LOGDROP
# confirm with a ping to east-in
ping -n -c 4 192.0.2.254
ipsec _stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east-x509-pluto-02
ipsec auto --status
ipsec auto --listall
echo "initdone"
