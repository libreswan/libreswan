ipsec whack --debug-whackwatch --name westnet-eastnet-ipv4 --initiate

ping -n -c 2 -I 192.0.1.254 192.0.2.254
ipsec look
echo done
