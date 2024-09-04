ipsec up westnet-eastnet
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ping -s 2000 -n -c 2 -I 192.0.1.254  192.0.2.254
echo done
