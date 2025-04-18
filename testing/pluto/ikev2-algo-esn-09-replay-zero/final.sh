# to make sure SADB is flushed by the kernel
sleep 2
# should be empty as the test is supposed to fail
ipsec _kernel state | grep replay
grep "netlink response" OUTPUT/$(hostname).pluto.log
