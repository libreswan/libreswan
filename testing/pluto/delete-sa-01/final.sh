../../guestbin/ipsec-look.sh
# up to 3.26 we printed a bogus message, this is checking that no longer happens
grep "received and ignored empty informational" /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
