# Two tunnels should have established with non-zero byte counters. East will have both of the road tunnels established
ipsec whack --trafficstatus 
grep "^[^|].* established Child SA" /tmp/pluto.log
grep "auth method: IKEv2_AUTH_" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
