../../guestbin/ipsec-look.sh
semodule -r ipsecspd
rm -rf ipsecspd.fc ipsecspd.if tmp
if [ -f /sbin/ausearch ]; then ausearch -ts recent -m AVC | audit2allow ; fi
