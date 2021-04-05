../../guestbin/ipsec-look.sh
sed -n -e '/IMPAIR: start processing duplicate packet/,/IMPAIR: stop processing duplicate packet/ { /^[^|]/ p }' /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
