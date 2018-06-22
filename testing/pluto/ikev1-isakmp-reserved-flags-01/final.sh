../../pluto/bin/ipsec-look.sh
# Should be 4 hits (3 main mode, 1 quick mode)  for both west (sending) and east (receiving)
grep ISAKMP_FLAG_MSG_RESERVED_BIT6 /tmp/pluto.log | wc -l
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
