/testing/guestbin/swan-prep
ipsec _stackmanager start
# make sure that clear text does not get through
iptables -A INPUT -i eth0 -s 192.0.2.0/24 -j LOGDROP
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
sleep 1
ipsec auto --add road-eastnet-nonat
ipsec auto --status
echo "initdone"
