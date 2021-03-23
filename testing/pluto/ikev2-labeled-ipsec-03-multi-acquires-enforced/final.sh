../../pluto/bin/ipsec-look.sh
../bin/check-for-core.sh
semodule -r ipsecspd
rm -rf tmp ipsecspd.fc ipsecspd.if
if [ -f /sbin/ausearch ]; then ausearch -ts recent -m AVC | audit2allow ; fi
