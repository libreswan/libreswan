: ==== cut ====
ipsec look # ../guestbin/ipsec-look.sh
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
