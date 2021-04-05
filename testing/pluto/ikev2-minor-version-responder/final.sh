../../guestbin/ipsec-look.sh
grep "minor version" /tmp/pluto.log >/dev/null && echo payload found
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
