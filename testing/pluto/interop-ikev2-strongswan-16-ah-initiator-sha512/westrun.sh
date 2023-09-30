strongswan up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# cannot use ../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh for strongswan
../../guestbin/ipsec-kernel-state.sh
ip xfrm policy
echo done
