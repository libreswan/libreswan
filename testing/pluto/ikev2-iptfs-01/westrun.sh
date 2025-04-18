ipsec auto --up ipv4-psk-ikev2
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus
ipsec _kernel state | grep iptfs
ip xfrm pol |grep iptfs
echo done
