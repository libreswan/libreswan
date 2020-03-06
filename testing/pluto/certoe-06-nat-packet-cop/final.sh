# A tunnel should have established with non-zero byte counters
hostname | grep nic > /dev/null || ipsec whack --trafficstatus
# you should see both RSA and NULL
grep -e IKEv2_AUTH_ -e ': authenticated using ' /tmp/pluto.log 
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
