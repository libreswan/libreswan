: ==== cut ====
ipsec auto --status
ipsec look
ipsec whack --shutdown
: ==== tuc ====
if [ -f /tmp/core ]; then echo CORE FOUND; mv /tmp/core /var/tmp; fi
: ==== end ====
