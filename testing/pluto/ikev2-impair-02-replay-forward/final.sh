../../guestbin/ipsec-look.sh
sed -n -e '/IMPAIR: start processing replay forward/,/IMPAIR: stop processing replay forward/ { /^[^|]/ p }' /tmp/pluto.log | grep -v 'message arrived'
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
