../../guestbin/ipsec-look.sh
# normally xfrmcheck should never fail, but this tests the test :)
../../guestbin/xfrmcheck.sh
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
