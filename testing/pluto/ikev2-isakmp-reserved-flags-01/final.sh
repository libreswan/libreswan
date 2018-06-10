../../pluto/bin/ipsec-look.sh
# Should be 2 hits for both west (sending) and east (receiving)
grep ISAKMP_FLAG_MSG_RESERVED_BIT6 /tmp/pluto.log >/dev/null && echo payload found
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
