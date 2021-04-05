../../guestbin/ipsec-look.sh
../../guestbin/xfrmcheck.sh
ipsec whack --shutdown
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
