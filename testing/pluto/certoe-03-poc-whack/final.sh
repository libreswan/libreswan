ipsec _kernel state
ipsec _kernel policy
hostname | grep nic > /dev/null || ipsec whack --trafficstatus
# A tunnel should have established
grep "^[^|].* established Child SA" /tmp/pluto.log
# you should see both RSA and NULL
grep -e 'auth method: ' -e 'hash algorithm identifier' -e "^[^|].* established IKE SA" /tmp/pluto.log
