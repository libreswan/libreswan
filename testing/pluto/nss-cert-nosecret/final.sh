certutil -L -d sql:/etc/ipsec.d
ipsec auto --listall
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
