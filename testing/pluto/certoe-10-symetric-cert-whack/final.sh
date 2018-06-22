# A tunnel should have established with non-zero byte counters
ipsec whack --trafficstatus 
grep "negotiated connection" /tmp/pluto.log
# you should see only Digital Signatures which supports only RSA now
grep IKEv2_AUTH_ OUTPUT/*pluto.log 
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
