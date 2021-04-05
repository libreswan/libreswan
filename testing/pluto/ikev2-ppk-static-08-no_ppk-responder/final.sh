hostname | grep east > /dev/null &&  grep "NO_PPK_AUTH verified" /tmp/pluto.log
ipsec whack --shutdown
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
