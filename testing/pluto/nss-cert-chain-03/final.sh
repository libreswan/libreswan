certutil -L -d sql:/etc/ipsec.d
# catch any cert chain specific leaks
ipsec whack --shutdown
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
