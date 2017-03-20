# --up will fail because of right=%any
ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
# Now we specify the remote ip, so the connection knows how to initiate
ipsec auto --remote-host 192.1.2.23 --up westnet-eastnet-ipv4-psk-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo done
