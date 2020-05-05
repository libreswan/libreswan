../../pluto/bin/ping-once.sh --up 192.1.2.23
ipsec auto --up road-east-x509-ipv4
../../pluto/bin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --rekey-ipsec --name road-east-x509-ipv4 --async
echo "sleep 40 seconds"
sleep 40
echo done
