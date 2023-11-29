ipsec auto --up northnet-eastnet-nat
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
sleep 5
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
sleep 5
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
sleep 5
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
sleep 5
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
sleep 5
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
sleep 5
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
# should not see any hits
grep R_U_THERE_ACK /tmp/pluto.log
echo done
