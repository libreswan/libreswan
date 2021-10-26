grep -i -e "^[^|].*SEC_ERROR" /tmp/pluto.log
: ==== cut ====
journalctl /sbin/ocspd --no-pager | tail -n 20 | grep ocspd
ipsec auto --status
: ==== tuc ====
