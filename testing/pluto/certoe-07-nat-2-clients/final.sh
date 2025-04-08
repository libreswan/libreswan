# A tunnel should have established with non-zero byte counters
../../guestbin/ping-once.sh --up 192.1.2.23
# jacob two two for east?
hostname | grep nic > /dev/null || ipsec whack --trafficstatus
ipsec _kernel state
ipsec _kernel policy
# you should see both RSA and NULL
grep -e 'auth method: ' -e 'hash algorithm identifier' -e "^[^|].* established IKE SA" /tmp/pluto.log
