: ==== cut ====
ipsec look # ../../pluto/bin/ipsec-look.sh
ipsec auto --status
: ==== tuc ====
ipsec whack --shutdown
: ==== cut ====
ipsec look # ../../pluto/bin/ipsec-look.sh
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
