../../guestbin/ipsec-look.sh
# tunnel should have been established
grep "^[^|].* established Child SA" /tmp/pluto.log
