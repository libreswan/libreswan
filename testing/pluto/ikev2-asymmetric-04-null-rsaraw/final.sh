grep -e 'auth method: ' -e 'hash algorithm identifier' -e ': authenticated using ' OUTPUT/*pluto.log
../../pluto/bin/ipsec-look.sh
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
