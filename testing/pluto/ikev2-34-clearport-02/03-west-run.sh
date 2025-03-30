ipsec auto --up west-east
# poke a hole to port 7, those packets will be allowed cleartext
ipsec auto --route pass-7
ipsec _kernel policy
# send packet over the clear exception - should return connection refused
echo 'test' | nc -w 5 192.1.2.23 7
# counters should be zero
ipsec trafficstatus
# send packet over the 'tunnel' should get encrypted
echo 'test' | nc -w 5 192.1.2.23 80
ipsec trafficstatus
# counters should be zero
echo done
