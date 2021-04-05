grep -e 'fragment number:' -e 'total fragments:' /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
