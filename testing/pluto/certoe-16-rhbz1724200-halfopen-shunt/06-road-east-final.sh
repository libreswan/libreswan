# a tunnel should have established
grep "^[^|].* established Child SA" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
