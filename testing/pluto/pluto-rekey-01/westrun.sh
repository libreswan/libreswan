ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# wait for an IKE rekey
sleep 45
sleep 45
# confirm rekey
ipsec whack --showstates
# ready for shutdown test in final.sh
echo done
