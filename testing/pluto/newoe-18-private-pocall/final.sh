../../guestbin/ipsec-look.sh
# should show tunnel
grep "negotiated connection" /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
