# east should show required PPK is missing
hostname | grep east > /dev/null && grep "PPK_ID not found" /tmp/pluto.log
ipsec whack --shutdown
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
