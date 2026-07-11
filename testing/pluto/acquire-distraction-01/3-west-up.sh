../../guestbin/ping-once.sh --forget -I 192.0.1.254 192.0.2.254
../../guestbin/wait-for.sh --match west-to-east -- ipsec whack --trafficstatus
ipsec whack --trafficstatus
