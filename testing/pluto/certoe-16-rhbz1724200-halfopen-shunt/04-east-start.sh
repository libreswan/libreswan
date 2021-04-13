# now start and trigger OE to road
iptables -I INPUT -p UDP --dport 500 -j DROP
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 7' -- ipsec auto --status
iptables -D INPUT -p UDP --dport 500 -j DROP
# trigger OE
ping -n -q -c 1 192.1.3.209
sleep 2
ping -n -q -c 2 192.1.3.209
sleep 2
ipsec trafficstatus
