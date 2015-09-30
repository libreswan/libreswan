ipsec whack --oppohere 192.1.2.45 --oppothere 192.1.2.23
ping -n -c 4 192.1.2.23
# should show traffic
ipsec whack --trafficstatus
echo done
