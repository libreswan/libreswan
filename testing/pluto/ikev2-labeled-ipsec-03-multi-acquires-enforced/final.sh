../../guestbin/ipsec-look.sh
semodule -r ipsecspd
rm -rf tmp ipsecspd.fc ipsecspd.if
if [ -f /sbin/ausearch ]; then ausearch -ts recent -m AVC | audit2allow ; fi
