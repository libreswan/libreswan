# on east this should show 2 sets of in/fwd/out policies
../../guestbin/ipsec-look.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
