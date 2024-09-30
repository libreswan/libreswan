sleep 5 # work-around broken ping
../../guestbin/ping-once.sh --up -I 192.0.1.251 192.0.2.254

../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
