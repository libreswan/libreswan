# ping my own ips
ping -n -c 1 -I 192.1.3.209 192.1.3.209
sleep 3
ping -n -c 1 -I 192.1.3.209 192.1.3.210
sleep 3
ping -n -c 1 -I 127.0.0.1 127.0.0.1
sleep 3
ipsec whack --shuntstatus
echo done
