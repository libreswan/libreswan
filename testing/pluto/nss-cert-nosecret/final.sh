certutil -L -d sql:/etc/ipsec.d
ipsec auto --listall
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
