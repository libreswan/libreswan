../../guestbin/ipsec-look.sh
semodule -r ipsecspd
rm -rf ipsecspd.fc ipsecspd.if tmp
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
