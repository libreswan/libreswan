# New files should have dropped in, and we are ready to restart
ipsec restart
../../guestbin/wait-until-pluto-started
ipsec status
# this assumes conection loaded with auto=ondemand
# trigger tunnel - the first trigger ping packet is lost
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
sleep 2
ping -n -q -c 4 -I 192.0.1.254 192.0.2.254
# show non-zero IPsec traffic counters
ipsec whack --trafficstatus
echo done
