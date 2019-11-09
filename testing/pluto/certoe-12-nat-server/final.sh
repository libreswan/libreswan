# A tunnel should have established with non-zero byte counters
ip addr show scope global
# jacob two two for east?
ipsec whack --trafficstatus 
ipsec whack --trafficstatus 
../../pluto/bin/ipsec-look.sh
# you should see both RSA and NULL
grep IKEv2_AUTH_ /tmp/pluto.log 
: ==== cut ====
ipsec auto --status
ipsec stop
#check the ip extra ip address/sourceip address is removed
ip addr show scope global
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
