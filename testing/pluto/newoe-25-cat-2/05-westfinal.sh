../../guestbin/ping-once.sh --up 10.0.10.1
ipsec whack --trafficstatus
iptables -t nat -L -n
../../guestbin/ipsec-look.sh
