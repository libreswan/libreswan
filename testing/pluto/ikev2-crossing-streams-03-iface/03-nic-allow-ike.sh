# wait a few seconds then allow IKE packet flow again
sleep 2
iptables -F
# give IKEs change to establish
sleep 10
