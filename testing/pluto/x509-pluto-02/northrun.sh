ipsec auto --up north-east-x509-pluto-02
ping -n -c 4 192.0.2.254
ipsec whack --trafficstatus
echo done
