# this test should log that west's certificate is revoked
grep "certificate revoked" /tmp/pluto.log
: ==== cut ====
journalctl /sbin/ocspd --no-pager | tail -n 20
ipsec auto --status
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
