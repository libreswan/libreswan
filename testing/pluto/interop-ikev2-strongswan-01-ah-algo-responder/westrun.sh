../../guestbin/libreswan-up-down.sh ah=md5 -I 192.0.1.254 192.0.2.254
../../guestbin/libreswan-up-down.sh ah=sha1 -I 192.0.1.254 192.0.2.254
# Test rekey
ipsec auto --add ah=sha1
ipsec auto --up ah=sha1
ping -n -q -c 2 -I 192.0.1.254 192.0.2.254
sleep 1
ipsec auto --up ah=sha1
sleep 1
ping -n -q -c 2 -I 192.0.1.254 192.0.2.254
# since bofh AH tunnels are still there, check if they all got traffic, meaning new ones was used
# use weird spacing to avoid sanitizer
ip xfrm     s | grep anti-replay
echo done
