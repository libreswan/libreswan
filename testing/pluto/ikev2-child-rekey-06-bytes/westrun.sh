ipsec auto --up west
# 20 pings will get to almost rekey
ping -W 4 -n -q -c 20 -I 192.0.1.254 192.0.2.254
# next ping will go over and initiate a rekey
ping -W 4 -n -q -c 1 -I 192.0.1.254 192.0.2.254
sleep 10
# expect #1 IKE #3 IPsec first rekeyed Child
ipsec whack --trafficstatus
ping -W 4 -n -q -c 28 -I 192.0.1.254 192.0.2.254
# expect #1 IKE #4 IPsec second rekeyed Child
ipsec whack --trafficstatus
echo done
