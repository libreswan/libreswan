ipsec auto --up west-east
# poke a hole to port 222, those packets will be allowed cleartext
ipsec auto --route pass-222
ip xfrm pol
# send packet over the clear exception - should return connection refused
echo 'test' | nc -v -w 5 192.1.2.23 222
# counters should be zero
ipsec trafficstatus
# send packet over the 'tunnel' should get encrypted
echo 'test' | nc -v -w 5 192.1.2.23 80
ipsec trafficstatus
# counters should be zero
echo done
