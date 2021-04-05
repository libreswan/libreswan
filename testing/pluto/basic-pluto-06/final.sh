: ==== cut ====
ipsec look # ../guestbin/ipsec-look.sh
ipsec auto --status
: ==== tuc ====
ipsec whack --shutdown
: ==== cut ====
ipsec look # ../guestbin/ipsec-look.sh
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
