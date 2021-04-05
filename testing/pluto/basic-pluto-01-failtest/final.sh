../../guestbin/ipsec-look.sh
# normally xfrmcheck should never fail, but this tests the test :)
../../guestbin/xfrmcheck.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
