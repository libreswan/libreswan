# ping should succeed
echo "north is sending pings"
ping -n -c 5 -I 192.1.3.33 192.1.2.23
echo "waiting while road sets up a tunnel to confirm there is no interference"
