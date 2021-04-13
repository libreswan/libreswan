ipsec auto --up west-east-delete1
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec auto --status | grep STATE_
echo "sleeping a bit.. 2"
sleep 2
ipsec whack --deletestate 2
echo "sleeping a bit.. 2"
sleep 2
ipsec auto --status | grep STATE_
ipsec whack --trafficstatus
echo done
