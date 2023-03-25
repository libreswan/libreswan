# on-demand packet triggers IKE to unavailable peer and is blocked
ipsec auto --route west-east
../../guestbin/ipsec-kernel-policy.sh

# poke a hole to port 7, those packets will be allowed cleartext
ipsec auto --route pass-7
../../guestbin/ipsec-kernel-policy.sh

# send packet over the clear exception - should return connection
# refused
echo 'test' | nc -w 5 192.1.2.23 7

# send packet over the 'tunnel' that's negotiating - should get
# blocked
echo 'test' | nc -w 5 192.1.2.23 80

echo done
