# A tunnel should have established with non-zero byte counters
hostname | grep nic > /dev/null || ipsec trafficstatus
../../pluto/bin/ipsec-look.sh
# you should see both RSA and NULL
grep -e 'auth method: ' -e 'hash algorithm identifier' -e ': authenticated using ' /tmp/pluto.log 
: ==== cut ====
ipsec auto --status
ipsec stop
#check the ip extra ip address/sourceip address is removed
ip addr show scope global
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
