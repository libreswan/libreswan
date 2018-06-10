# A tunnel should have established with non-zero byte counters
ping -n -c 4 192.1.2.23
# jacob two two for east?
ipsec whack --trafficstatus 
ipsec whack --trafficstatus 
../../pluto/bin/ipsec-look.sh
# you should see both RSA and NULL
grep IKEv2_AUTH_ /tmp/pluto.log 
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
