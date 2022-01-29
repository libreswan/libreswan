../../guestbin/ipsec-look.sh
# should show tunnel
grep "^[^|].* established Child SA" /tmp/pluto.log
