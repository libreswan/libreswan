ipsec auto --up  westnet-eastnet-x509-chain
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec auto --listall | grep 'subject.*east_chain_inter'
ipsec auto --listall | grep 'ID_DER_ASN1_DN.*east'
echo done
