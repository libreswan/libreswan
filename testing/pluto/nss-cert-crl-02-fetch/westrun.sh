ipsec auto --up nss-cert-crl
ping -n -c2 -I 192.0.1.254 192.0.2.254
ipsec auto --down nss-cert-crl
sleep 2
ipsec auto --up nss-cert-crl
echo done
