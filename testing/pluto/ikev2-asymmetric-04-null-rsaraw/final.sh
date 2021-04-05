grep -e 'auth method: ' -e 'hash algorithm identifier' -e ': authenticated using ' OUTPUT/*pluto.log
../../guestbin/ipsec-look.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
