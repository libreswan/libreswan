# A tunnel should have established with non-zero byte counters
hostname | grep nic > /dev/null || ipsec trafficstatus
../../guestbin/ipsec-kernel-state.sh\n../../guestbin/ipsec-kernel-policy.sh
# you should see both RSA and NULL
grep -e 'auth method: ' -e 'hash algorithm identifier' -e "^[^|].* established IKE SA" /tmp/pluto.log 
