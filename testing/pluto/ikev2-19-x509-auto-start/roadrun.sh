ipsec auto --up road-east-ipv4-ikev2
ping -n -c 2 -I 192.0.1.254 192.0.2.254
# waiting 4 minutes in chunks of 15 seconds
sleep 15
sleep 15
sleep 15
sleep 15
echo one minute
sleep 15
sleep 15
sleep 15
sleep 15
echo two minutes
sleep 15
sleep 15
sleep 15
sleep 15
echo three minutes
echo 15
echo 15
echo 15
echo 15
echo four minutes
echo 15
ipsec auto --status | grep road-east-ipv4-ikev2
echo done
