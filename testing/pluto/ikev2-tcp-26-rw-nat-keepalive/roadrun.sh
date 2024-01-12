ipsec up road

../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --impair send_keepalive:1
../../guestbin/ping-once.sh --up 192.0.2.254

../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
echo done
