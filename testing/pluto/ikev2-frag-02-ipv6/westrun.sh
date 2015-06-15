ipsec auto --up  v6-tunnel
ping6 -n -c 4 -I 2001:db8:1:2::45 2001:db8:1:2::23
grep "fragment number" /tmp/pluto.log
echo done
