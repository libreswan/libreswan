ipsec auto --up  loopback-west
ipsec look
tcpdump -i lo -n -c 6 2> /dev/null &
ping6 -n -c 4 ::1
# should be exacly 2
grep "IPsec SA established" /tmp/pluto.log | wc -l
echo done
