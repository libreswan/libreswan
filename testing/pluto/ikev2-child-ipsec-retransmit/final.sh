# should show retransmits on west and replies on east
grep sending /tmp/pluto.log |grep through
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
