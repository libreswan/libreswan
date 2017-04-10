ping -q -c 1 192.1.2.254
time dig east.testing.libreswan.org
time dig east.testing.libreswan.org IPSECKEY
time dig +short @192.1.2.254 east.testing.libreswan.org
dig +short @192.1.2.254 chaos version.server txt
dig +short @192.1.2.254 -p 5353 east.testing.libreswan.org
dig +short @192.1.2.254 -p 5353 chaos version.server txt
echo done
