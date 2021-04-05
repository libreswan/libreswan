../../guestbin/ipsec-look.sh
ipsec stop
grep -e '; already' -e 'discarding packet' /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
