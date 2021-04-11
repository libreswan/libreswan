# A tunnel should have established with non-zero byte counters
ipsec whack --trafficstatus 
grep "negotiated connection" /tmp/pluto.log
grep -e 'auth method: ' -e 'hash algorithm identifier' -e ': authenticated using ' OUTPUT/*pluto.log 
: ==== cut ====
ipsec auto --status
: ==== tuc ====
: ==== end ====
