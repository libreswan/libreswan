# now start and trigger OE to road
iptables -I INPUT -p UDP --dport 500 -j DROP
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
iptables -D INPUT -p UDP --dport 500 -j DROP
# trigger OE
ping -n -c3 192.1.3.209
sleep 3
ipsec trafficstatus
