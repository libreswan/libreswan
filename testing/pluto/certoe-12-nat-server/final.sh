# A tunnel should have established with non-zero byte counters
hostname | grep nic > /dev/null || ipsec trafficstatus
ipsec _kernel state
ipsec _kernel policy
# you should see both RSA and NULL
grep -e 'auth method: ' -e 'hash algorithm identifier' -e "^[^|].* established IKE SA" /tmp/pluto.log 
