: ==== cut ====
ipsec auto --status
ipsec look # ../../pluto/bin/ipsec-look.sh
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
