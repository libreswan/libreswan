ipsec auto --up westnet-eastnet-gcm
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
echo done
