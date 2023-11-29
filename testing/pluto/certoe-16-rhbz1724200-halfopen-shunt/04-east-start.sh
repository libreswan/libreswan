# now start and trigger OE to road
iptables -I INPUT -p UDP --dport 500 -j DROP
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 7' -- ipsec auto --status
iptables -D INPUT -p UDP --dport 500 -j DROP
# trigger OE
../../guestbin/ping-once.sh --forget 192.1.3.209
../../guestbin/ping-once.sh --up 192.1.3.209
sleep 3
ipsec trafficstatus
