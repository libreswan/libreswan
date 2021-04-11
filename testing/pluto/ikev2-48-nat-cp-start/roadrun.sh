# wait for autostart to complete
../../guestbin/wait-for.sh --match 192.0.2.1 -- ipsec whack --trafficstatus

# ipsec will configure 192.0.2.1 on eth0
ip -4 route
ip addr show  dev eth0
../../guestbin/ping-once.sh --up 192.0.2.1 192.1.2.23

ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
#check if the address, 192.0.2.1, is removed
ip addr show  dev eth0
echo done
