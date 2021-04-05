../../guestbin/ipsec-look.sh
# ==== cut ====
ipsec auto --status | grep westnet-eastnet-compress
# ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
