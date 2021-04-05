../../guestbin/ipsec-look.sh
# ==== cut ====
ipsec auto --status
# ==== tuc ====
ipsec whack --shutdown
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
