ipsec auto --up v6-transport
echo "transmitted test" | nc -p 1701 -s 2001:db8:1:2::45 2001:db8:1:2::23 1701
echo done
