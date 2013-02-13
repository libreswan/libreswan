: ==== cut ====
ipsec auto --status
ipsec look
certutil -L -d /etc/ipsec.d
if [ -f /tmp/core* ]; then echo CORE FOUND; mv /tmp/core* ./; fi
: ==== tuc ====

: ==== end ====

