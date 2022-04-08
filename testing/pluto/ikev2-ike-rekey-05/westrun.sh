ipsec auto --up westnet-eastnet-a
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec auto --up westnet-eastnet-b
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254
ipsec auto --up westnet-eastnet-c
../../guestbin/ping-once.sh --up -I 192.0.101.254 192.0.201.254
ipsec whack --trafficstatus
ipsec showstates
echo sleep 3m
sleep 60
sleep 60
sleep 60
ipsec whack --trafficstatus
ipsec showstates
sleep 60
ipsec whack --trafficstatus
ipsec showstates
sleep 60
sleep 60
sleep 60
sleep 60
sleep 60
echo done
