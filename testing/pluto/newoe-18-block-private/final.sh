../../guestbin/ipsec-look.sh
# should not show any hits because block prevents trigger
grep "initiate on demand" /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
