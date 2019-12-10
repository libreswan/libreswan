ipsec auto --up west
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "sleep 9"
sleep 9
ipsec whack --rekey-ipsec --name west
sleep 2
# expect #1 IKE #3 IPsec
ipsec status |grep STATE_
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "sleep 11"
sleep 11
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --rekey-ipsec --name west
sleep 2
# expect #1 IKE #4 IPsec
ipsec status |grep STATE_
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done
