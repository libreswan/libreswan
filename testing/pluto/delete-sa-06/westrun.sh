# wait for east to initiate to us
sleep 10
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# should show non-zero traffic counters
ipsec whack --trafficstatus
# sending delete/notify should cause east to re-initiate
ipsec auto --down westnet-eastnet
# give Delete/Notify some time
sleep 5
# A new IPsec SA should be established (older versions would take 30 seconds)
# traffic counters should be zero
ipsec whack --trafficstatus
