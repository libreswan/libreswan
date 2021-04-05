# verify protoport selectors are there
../../guestbin/ipsec-look.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
