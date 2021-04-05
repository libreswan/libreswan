../../guestbin/ipsec-look.sh
# tunnel should have been established
grep "negotiated connection" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
