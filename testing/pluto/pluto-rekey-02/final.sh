../../guestbin/ipsec-look.sh | sed "s/port [0-9][0-9][0-9][0-9][0-9]/port XPORT/"
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
