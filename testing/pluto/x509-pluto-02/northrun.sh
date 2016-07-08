ipsec auto --up north-east-x509-pluto-02
ping -n -c 4 -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus
echo done
