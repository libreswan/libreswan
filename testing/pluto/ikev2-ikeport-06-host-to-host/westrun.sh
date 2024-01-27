ipsec auto --up west-east-ikev2
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec whack --trafficstatus
# double check IKE messages still work by sending rekey request
ipsec whack --rekey-child --name west-east-ikev2
echo done
