: ==== cut ====
# On nic, this will show relevant OCSP responses
journalctl /sbin/ocspd --no-pager | tail -n 20 | grep ocspd
ipsec auto --status
: ==== tuc ====
