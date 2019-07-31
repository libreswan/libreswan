# ping should succeed
echo "north is sending pings again"
ping -n -c 5 -I 192.1.3.33 192.1.2.23
echo "pings sent"
