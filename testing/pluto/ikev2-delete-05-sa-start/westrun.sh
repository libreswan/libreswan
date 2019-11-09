# wait for the connection to come up
../../pluto/bin/wait-for-whack-trafficstatus.sh --timeout 30 westnet-eastnet-auto

# ensure that clear text does not get through
iptables -A INPUT -i eth1 -m policy --dir in --pol none -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT

# We expect ping to be encrypted and work; we should see non-zero
# traffic counters
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus

# sending delete/notify should cause east to re-initiate
ipsec auto --down westnet-eastnet-auto

# give Delete/Notify some time; traffic counters on the new IPsec SA
# should be 0
../../pluto/bin/wait-for-whack-trafficstatus.sh --timeout 5 'westnet-eastnet-auto.*inBytes=0'

# A new IPsec SA should be established (older versions would be dead for 30 seconds)
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done
