ipsec auto --up westnet-eastnet-ipv4-psk-ppk
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --down westnet-eastnet-ipv4-psk-ppk
ipsec auto --delete westnet-eastnet-ipv4-psk-ppk
echo done
