ipsec auto --up ipv4-psk-ikev2
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus
(ip xfrm state |grep iptfs) || echo "ok, no iptfs"
(ip xfrm pol |grep iptfs) || echo "ok, no iptfs"
echo done
