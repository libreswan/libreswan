../../guestbin/ipsec-look.sh
# should not show any hits
grep -v '^|' /tmp/pluto.log | grep "^[^|].*: established Child SA"
