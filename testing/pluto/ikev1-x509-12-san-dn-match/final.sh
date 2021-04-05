# confirm the right ID types were sent/received
grep "ID type" /tmp/pluto.log | sort | uniq
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
