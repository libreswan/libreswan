: dump key-length attributes to the connsole - none can be zero
grep -A 1 'af+type: AF+IKEv2_KEY_LENGTH' /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
