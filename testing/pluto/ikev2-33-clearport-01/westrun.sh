# on-demand packet triggers IKE to unavailable peer and is blocked 
ipsec auto --route west-east
# poke a hole to port 222, those packets will be allowed cleartext
ipsec auto --route pass-222
ip xfrm pol
# send packet over the clear exception - should return connection refused
echo 'test' | nc -v -w 5 192.1.2.23 222
# send packet over the 'tunnel' that's negotiating - shoudl get blocked
echo 'test' | nc -v -w 5 192.1.2.23 80
echo done
