: ==== start ====

# confirm that the network is alive
ping -n -c 4 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
# confirm with a ping to east-in
ping -n -c 4 192.0.2.254

/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started

iptables -I OUTPUT -f -d 192.1.2.23 -j LOGDROP
ipsec auto --add westnet-eastnet-x509-fragmentation
ipsec auto --status
echo "initdone"
