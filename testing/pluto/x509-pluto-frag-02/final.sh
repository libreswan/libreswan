grep "fragment" /tmp/pluto.log | grep -v delref
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
