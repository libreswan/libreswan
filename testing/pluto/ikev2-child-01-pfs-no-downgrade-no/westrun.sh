ipsec auto --up westnet-eastnet-ikev2
../../pluto/bin/one-ping.sh -I 192.0.1.254 192.0.2.254

# remote pfs=no downgrade=no

# pfs=no downgrade=no - connect
ipsec auto --up westnet-eastnet-ikev2-00
../../pluto/bin/one-ping.sh -I 192.0.100.254 192.0.200.254

# pfs=no downgrade=yes - connect
ipsec auto --up westnet-eastnet-ikev2-01
../../pluto/bin/one-ping.sh -I 192.0.101.254 192.0.201.254

# pfs=yes downgrade=no - fail
# ipsec auto --up westnet-eastnet-ikev2-10
# ../../pluto/bin/one-ping.sh -I 192.0.110.254 192.0.210.254

# pfs=yes downgrade=yes - connect
ipsec auto --up westnet-eastnet-ikev2-11
../../pluto/bin/one-ping.sh -I 192.0.111.254 192.0.211.254

ipsec whack --trafficstatus

echo done
