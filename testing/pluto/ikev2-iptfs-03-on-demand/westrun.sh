ipsec auto --route ipv4-psk-ikev2
# ping will get eaten
../../guestbin/ping-once.sh --fire-and-forget -I 192.1.2.45 192.1.2.23
ip xfrm state |grep iptfs
ip xfrm pol |grep iptfs
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
echo done
