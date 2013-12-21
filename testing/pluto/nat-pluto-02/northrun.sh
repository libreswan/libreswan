ipsec auto --route north-east-pass
ipsec auto --up  north-east-port19
ipsec eroute
echo "This should be encrypted across the machines" | nc -w 3 192.1.2.23 19 
echo "This should be plaintext across the machines" | nc -w 3 192.1.2.23 20
echo done
