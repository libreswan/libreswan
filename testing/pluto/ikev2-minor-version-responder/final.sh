../../guestbin/ipsec-look.sh
grep "minor version" /tmp/pluto.log >/dev/null && echo payload found
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
