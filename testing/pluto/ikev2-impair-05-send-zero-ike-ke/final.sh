grep -e v2N_INVALID_KE_PAYLOAD -e v2N_INVALID_SYNTAX /tmp/pluto.log | grep -v -e '^|'
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
