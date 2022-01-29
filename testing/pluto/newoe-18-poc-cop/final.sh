../../guestbin/ipsec-look.sh
# a tunnel should have established
grep "^[^|].* established Child SA" /tmp/pluto.log
