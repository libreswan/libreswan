: ==== cut ====
ipsec auto --status
ipsec look # ../guestbin/ipsec-look.sh
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
