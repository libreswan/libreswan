ipsec up west

../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

# wait for rekey event
ipsec whack --rekey-ike --name west

# rekey of IKE SA leaves traffic counts unchanged
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus

../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
