# Two tunnels should have established with non-zero byte counters. East will have both of the road tunnels established
ipsec whack --trafficstatus 
grep "negotiated connection" /tmp/pluto.log
grep IKEv2_AUTH_ OUTPUT/*pluto.log 
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
