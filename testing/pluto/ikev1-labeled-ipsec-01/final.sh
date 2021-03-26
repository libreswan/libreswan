../../pluto/bin/ipsec-look.sh
ipsec whack --shutdown
semodule -r ipsecspd
rm -rf ipsecspd.fc ipsecspd.if tmp
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -ts recent -m AVC | audit2allow ; fi
