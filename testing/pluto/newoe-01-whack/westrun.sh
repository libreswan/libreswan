ipsec whack --oppohere 192.1.2.45 --oppothere 192.1.2.23
ping -n -c 4 192.1.2.23
sleep 3 # kernel takes time to count
# should show traffic
ipsec whack --trafficstatus
echo done
