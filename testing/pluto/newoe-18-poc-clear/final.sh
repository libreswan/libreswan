../../guestbin/ipsec-look.sh
# should not show any hits
grep -v '^|' /tmp/pluto.log | grep "negotiated connection"
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
