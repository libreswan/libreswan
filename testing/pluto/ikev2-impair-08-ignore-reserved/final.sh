hostname | grep east > /dev/null && grep "byte at offset" /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
