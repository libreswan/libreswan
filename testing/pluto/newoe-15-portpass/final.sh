../../guestbin/ipsec-look.sh
# A tunnel should have established
grep "negotiated connection" /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
