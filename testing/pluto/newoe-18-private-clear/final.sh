../../guestbin/ipsec-look.sh
# should not show any hits
grep "^[^|].* established Child SA" /tmp/pluto.log
