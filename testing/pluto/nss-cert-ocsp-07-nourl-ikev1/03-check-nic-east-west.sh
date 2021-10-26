# on east, revocation should show up
hostname | grep east && grep "certificate revoked" /tmp/pluto.log
# should show a hit
hostname |grep east && grep ERROR /tmp/pluto.log
# should not show a hit
hostname |grep nic && journalctl /sbin/ocspd --no-pager | tail -n 20 |grep TRYLATER
: ==== cut ====
journalctl /sbin/ocspd --no-pager | tail -n 20
# tunnel should not show up
ipsec status
: ==== tuc ====
