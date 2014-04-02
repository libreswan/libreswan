ipsec auto --up  loopback-westleft
ipsec look
tcpdump -i lo -n -c 2 2> /dev/null &
nc -l 127.0.0.1 4300 &
sleep 1
echo test | nc 127.0.0.1 4300
# should be exacly 2
grep "IPsec SA established" /tmp/pluto.log | wc -l
echo done
