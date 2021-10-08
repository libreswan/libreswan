# wait for autostart to complete
../../guestbin/wait-for.sh --match 192.0.2.1 -- ipsec whack --trafficstatus

# ipsec will configure 192.0.2.1->192.1.2.23 on eth0
../../guestbin/ping-once.sh --up 192.1.2.23
