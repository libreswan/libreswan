ipsec look
: ==== cut ====
ipsec auto --status
: ==== tuc ====
ipsec stop
# show no nflog left behind
iptables -L -n
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
