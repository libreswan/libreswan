sleep 5
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../guestbin/ipsec-look.sh
# ping should succeed through tunnel after triggering
ping -n -c 1 -I 192.1.3.209 192.1.2.23
ping -n -c 1 -I 192.1.3.209 192.1.2.45
sleep 3
ping -n -c 3 -I 192.1.3.209 192.1.2.23
ping -n -c 3 -I 192.1.3.209 192.1.2.45
echo done
