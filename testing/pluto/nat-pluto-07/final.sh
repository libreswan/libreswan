../../guestbin/ipsec-look.sh | sed "s/dport [0-9][0-9][0-9][0-9][0-9]/dport DPORT/"
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
