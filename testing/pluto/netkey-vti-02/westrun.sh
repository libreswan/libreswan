ipsec auto --up westnet-eastnet-vti-01
ipsec auto --up westnet-eastnet-vti-02
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 10.0.1.254 10.0.2.254
ipsec whack --trafficstatus
echo done
