sleep 5
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../guestbin/ipsec-look.sh
# ping should succeed through tunnel
ping -n -c 4 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
echo done
