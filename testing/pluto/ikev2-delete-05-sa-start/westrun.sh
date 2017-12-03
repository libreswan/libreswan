# wait for east to initiate to us
sleep 20
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -m policy --dir in --pol none -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# We expect ping to be encrypted and work
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# we should see non-zero traffic counters
ipsec whack --trafficstatus
# sending delete/notify should cause east to re-initiate 
ipsec auto --down westnet-eastnet-auto
# give Delete/Notify some time
sleep 5
# traffic counters on the new IPsec SA should be 0
ipsec whack --trafficstatus
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# A new IPsec SA should be established (older versions would be dead for 30 seconds)
ipsec whack --trafficstatus
sleep 20
ipsec whack --trafficstatus
echo done
