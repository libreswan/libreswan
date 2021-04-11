# one ping will get lost in the ondemand as only TCP is cached
ping6 -n -q -c 4 -I 2001:db8:1:2::45 2001:db8:1:2::23
../../guestbin/ipsec-look.sh
echo done
