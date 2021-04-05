../../guestbin/ipsec-look.sh
# should not show any hits because block prevents poc from seeing traffic
grep "initiate on demand" /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
