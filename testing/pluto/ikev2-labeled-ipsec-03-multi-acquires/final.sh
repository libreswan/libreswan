../../pluto/bin/ipsec-look.sh
semodule -r ipsecspd
rm -rf tmp ipsecspd.fc ipsecspd.if
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -ts recent -m AVC | audit2allow ; fi
