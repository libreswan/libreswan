# this test should log that west's certificate is revoked
grep -i "certificate revoked" /tmp/pluto.log
: ==== cut ====
journalctl /sbin/ocspd --no-pager | tail -n 20
ipsec auto --status
: ==== tuc ====
