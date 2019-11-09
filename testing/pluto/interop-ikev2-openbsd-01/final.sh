# check output on openbsd end
test -f /sbin/ipsecctl && ipsecctl -s all  
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
