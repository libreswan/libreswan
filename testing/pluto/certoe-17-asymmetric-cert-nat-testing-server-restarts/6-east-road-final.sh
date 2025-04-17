# A tunnel should have established with non-zero byte counters
ipsec whack --trafficstatus 
grep "^[^|].* established Child SA" /tmp/pluto.log
grep -e 'auth method: ' -e 'hash algorithm identifier' -e "^[^|].* established IKE SA" OUTPUT/*pluto.log 
: ==== cut ====
ipsec auto --status
: ==== tuc ====
