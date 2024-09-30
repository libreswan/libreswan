../../guestbin/prep.sh

ifconfig sec1 create
ifconfig sec1 inet 192.0.2.254/24 192.0.1.251
ifconfig sec1 up

ifconfig sec1
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

../../guestbin/iked.sh start

echo "initdone"
