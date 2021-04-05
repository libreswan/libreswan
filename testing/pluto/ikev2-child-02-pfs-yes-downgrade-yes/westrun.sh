ipsec auto --up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

# remote pfs=no downgrade=no

# pfs=no downgrade=no - connect
ipsec auto --up westnet-eastnet-ikev2-00
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254

# pfs=no downgrade=yes - connect
ipsec auto --up westnet-eastnet-ikev2-01
../../guestbin/ping-once.sh --up -I 192.0.101.254 192.0.201.254

# pfs=yes downgrade=no
ipsec auto --up westnet-eastnet-ikev2-10
../../guestbin/ping-once.sh --up -I 192.0.110.254 192.0.210.254

# pfs=yes downgrade=yes - connect
ipsec auto --up westnet-eastnet-ikev2-11
../../guestbin/ping-once.sh --up -I 192.0.111.254 192.0.211.254

ipsec whack --trafficstatus

echo done
