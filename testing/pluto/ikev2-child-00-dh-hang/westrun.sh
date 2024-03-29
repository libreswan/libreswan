ipsec auto --up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

# remote pfs=no downgrade=no

# pfs=no - fail
ipsec auto --up westnet-eastnet-ikev2-00
#../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254

# pfs=yes - connect
ipsec auto --up westnet-eastnet-ikev2-10
../../guestbin/ping-once.sh --up -I 192.0.110.254 192.0.210.254

ipsec whack --trafficstatus

echo done
