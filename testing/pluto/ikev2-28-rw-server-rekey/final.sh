hostname | grep east > /dev/null && ipsec whack --rekey-ipsec --name road-eastnet-nonat
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
