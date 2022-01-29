../../guestbin/ipsec-look.sh
# A tunnel should have established
grep "^[^|].* established Child SA" /tmp/pluto.log
