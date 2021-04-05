../../guestbin/ipsec-look.sh
# a tunnel should show up here
grep "negotiated connection" /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
