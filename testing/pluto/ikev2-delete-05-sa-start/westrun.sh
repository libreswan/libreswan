# wait for the connection to come up
../../pluto/bin/wait-for.sh --match westnet-eastnet-auto -- ipsec whack --trafficstatus
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -m policy --dir in --pol none -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# We expect ping to be encrypted and work; we should see non-zero
# traffic counters
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# sending delete/notify should cause east to re-initiate
ipsec auto --down westnet-eastnet-auto
# give Delete/Notify some time; traffic counters on the new IPsec SA
# should be 0
../../pluto/bin/wait-for.sh --match 'westnet-eastnet-auto.*inBytes=0' -- ipsec whack --trafficstatus
# A new IPsec SA should be established (older versions would be dead for 30 seconds)
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
