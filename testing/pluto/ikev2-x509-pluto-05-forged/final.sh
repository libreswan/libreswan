# should confirm failure
hostname | grep east && grep "Signature check" /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
