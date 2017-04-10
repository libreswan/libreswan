ping -q -c 1 192.1.2.254
time dig east.libreswan.org
time dig east.libreswan.org IPSECKEY
time dig @192.1.2.254 east.libreswan.org
time dig @192.1.2.254 -p 5353  east.libreswan.org
echo done
