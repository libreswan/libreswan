# confirm the right ID types were sent/received
grep "ID type" /tmp/pluto.log | sort | uniq
: ==== cut ====
ipsec auto --status
ipsec stop
strongswan stop
: ==== tuc ====
