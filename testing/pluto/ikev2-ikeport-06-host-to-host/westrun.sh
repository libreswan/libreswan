ipsec auto --up west-east-ikev2
ping -n -q -c 4 192.1.2.23
ipsec whack --trafficstatus
# double check IKE messages still work by sending rekey request
ipsec whack --rekey-ipsec --name west-east-ikev2
echo done
