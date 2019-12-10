ipsec auto --up west
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "sleep 13"
sleep 13
ipsec whack --rekey-ike --name west
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec status |grep STATE_
# expect #2 IPsec #3 IKE
echo "sleep 21"
sleep 21
ipsec whack --rekey-ike --name west
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec status |grep STATE_
# expect #2 IPsec #4 IKE
echo done
