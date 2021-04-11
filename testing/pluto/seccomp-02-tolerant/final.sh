certutil -L -d sql:/etc/ipsec.d/
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
