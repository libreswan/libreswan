# A tunnel should have established with non-zero byte counters
hostname | grep nic > /dev/null || ipsec whack --trafficstatus
hostname | grep nic > /dev/null || grep "^[^|].* established Child SA" /tmp/pluto.log
hostname | grep nic > /dev/null || grep -e 'auth method: ' -e 'hash algorithm identifier' -e "^[^|].* established IKE SA" /tmp/pluto.log 
