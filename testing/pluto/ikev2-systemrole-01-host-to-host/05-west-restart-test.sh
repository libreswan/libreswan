# New files should have dropped in, and we are ready to restart
ipsec restart
../../guestbin/wait-until-pluto-started
ipsec status
# this assumes connection loaded with auto=ondemand
# trigger tunnel - the first trigger ping packet is lost
../../guestbin/ping-once.sh --down -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match 192.1.2.45-to-192.1.2.23 -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# show non-zero IPsec traffic counters
ipsec whack --trafficstatus
echo done
