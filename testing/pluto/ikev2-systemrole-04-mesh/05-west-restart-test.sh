# New files should have dropped in, and we are ready to restart
ipsec restart
../../guestbin/wait-until-pluto-started
# give OE a chance to load
sleep 3
ipsec status
# trigger OE
ping -n -q -c 4 -I 192.1.2.45 192.1.2.23
# show non-zero IPsec traffic counters
ipsec whack --trafficstatus
echo done
