../../guestbin/ipsec-look.sh
# tunnel should have been established once - idleness check should prevent rekeying for OE
grep "negotiated connection" /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
