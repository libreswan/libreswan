../../guestbin/ipsec-look.sh
sed -n -e '/IMPAIR: start processing replay forward/,/IMPAIR: stop processing replay forward/ { /^[^|]/ p }' /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
