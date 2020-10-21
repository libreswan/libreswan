# the actual testing to trigger the tunnel
# No tunnel should be up
ipsec whack --trafficstatus
# trigger tunnel - the first trigger ping packet is lost
ping -n -c 4 -I 192.1.2.45 192.1.2.23
# show non-zero IPsec traffic counters
ipsec whack --trafficstatus
echo done
