../../pluto/bin/ipsec-look.sh
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -ts recent -m AVC | audit2allow ; fi
