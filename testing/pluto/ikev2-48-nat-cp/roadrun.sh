ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
# AA see really weird route, I have to remove that
route -n
route del -net 192.1.2.23 netmask 255.255.255.255
# ipsec will configure 192.0.2.1 on eth0
ip addr show  dev eth0
../../guestbin/ping-once.sh --up -I 192.0.2.1 192.1.2.23
ipsec whack --trafficstatus
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
#check if the address, 192.0.2.1, is removed
ip addr show  dev eth0
echo done
