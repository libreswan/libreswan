ipsec auto --up west-east-delete1
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
../../guestbin/ipsec-kernel-policy.sh
ipsec whack --showstates
