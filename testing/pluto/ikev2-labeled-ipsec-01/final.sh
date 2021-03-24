../../pluto/bin/ipsec-look.sh
semodule -r ipsecspd
rm -rf ipsecspd.fc ipsecspd.if tmp
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
