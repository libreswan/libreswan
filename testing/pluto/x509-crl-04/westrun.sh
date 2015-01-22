ipsec auto --up westnet-eastnet-x509-cr
ipsec auto --replace westnet-eastnet-x509-cr
ipsec auto --up westnet-eastnet-x509-cr
ping -n -c 4 192.0.2.254
ipsec look
