ipsec auto --up westnet-northnet
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
# block west
iptables -I INPUT -s 192.1.2.45 -j DROP
iptables -I OUTPUT -d 192.1.2.45 -j DROP
sleep 60
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
# unblock west
iptables -D INPUT -s 192.1.2.45 -j DROP
iptables -D OUTPUT -d 192.1.2.45 -j DROP
sleep 60
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
# block east
iptables -I INPUT -s 192.1.2.23 -j DROP
iptables -I OUTPUT -d 192.1.2.23 -j DROP
sleep 60
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
# unblock east
iptables -D INPUT -s 192.1.2.23 -j DROP
iptables -D OUTPUT -d 192.1.2.23 -j DROP
sleep 60
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
# block both
iptables -I INPUT -s 192.1.2.45 -j DROP
iptables -I OUTPUT -d 192.1.2.45 -j DROP
iptables -I INPUT -s 192.1.2.23 -j DROP
iptables -I OUTPUT -d 192.1.2.23 -j DROP
sleep 60
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --down -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --down -I 192.0.3.254 192.1.4.45
# unblock west
iptables -D INPUT -s 192.1.2.45 -j DROP
iptables -D OUTPUT -d 192.1.2.45 -j DROP
sleep 60
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
# unblock east
iptables -D INPUT -s 192.1.2.23 -j DROP
iptables -D OUTPUT -d 192.1.2.23 -j DROP
sleep 60
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
