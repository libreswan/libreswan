: ==== cut ====
ipsec auto --status
cat /tmp/pluto.log
: ==== tuc ====
if [ -f /tmp/core ]; then echo CORE FOUND; mv /tmp/core /var/tmp; fi
