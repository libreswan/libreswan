ipsec auto --up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

# remote pfs=no dh=none

# pfs=no dh= - connect
ipsec auto --up 'westnet-eastnet-ikev2-pfs=no-esp=aes'
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254

# pfs=no dh=none - connect
ipsec auto --up 'westnet-eastnet-ikev2-pfs=no-esp=aes;none'
../../guestbin/ping-once.sh --up -I 192.0.101.254 192.0.201.254

# pfs=yes dh= - connect
ipsec auto --up 'westnet-eastnet-ikev2-pfs=yes-esp=aes'
../../guestbin/ping-once.sh --up -I 192.0.110.254 192.0.210.254

# pfs=yes dh=none - connect
ipsec auto --up 'westnet-eastnet-ikev2-pfs=yes-esp=aes;none'
../../guestbin/ping-once.sh --up -I 192.0.111.254 192.0.211.254

ipsec whack --trafficstatus

echo done
