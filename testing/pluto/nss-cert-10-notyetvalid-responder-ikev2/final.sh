# only expected to show failure on west
grep "certificate payload rejected" /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
