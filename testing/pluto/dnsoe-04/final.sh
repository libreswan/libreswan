# A tunnel should have established with non-zero byte counters
ipsec whack --trafficstatus
grep "negotiated connection" /tmp/pluto.log
# you should see one RSA and on NULL only
grep IKEv2_AUTH_ /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
