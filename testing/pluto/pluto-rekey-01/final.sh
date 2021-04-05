# specifically test shutting down after rekey doesn't crash
ipsec stop
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
