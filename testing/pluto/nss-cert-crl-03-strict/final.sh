crlutil -L -d sql:/etc/ipsec.d | grep mainca
ipsec auto --listcrls | grep issuer
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
