ping -n -q -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE to install %pass due to east not running ipsec
sleep 10
# should show no tunnels and a bare shunt
ipsec trafficstatus
ipsec shuntstatus
# verify xfrm policy got added for %pass
../../guestbin/ipsec-look.sh
echo "waiting on east to start ipsec and OE initiate to us"
