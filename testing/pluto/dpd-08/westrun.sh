# we can transmit in the clear
ping -n -q -c 4 192.1.2.23
# bring up the tunnel
ipsec auto --up west-east
# use the tunnel
ping -n -q -c 4 192.1.2.23
# show the tunnel!
echo "Tunnel should be up"
ipsec whack --trafficstatus
# Let R_U_THERE packets flow
echo "Waiting 15 seconds..."
sleep 15
echo "Crashing east"
ssh 192.1.2.23 ipsec stop # should really use the new *.sh functionality
echo "Waiting to see if we detect phase2 is still up - no DPD restart"
sleep 15
sleep 15
sleep 15
sleep 15
ssh 192.1.2.23 ip xfrm state flush
echo "Waiting to see if we detect phase2 is gone - DPD restarts"
sleep 15
sleep 15
sleep 15
sleep 15
echo done
