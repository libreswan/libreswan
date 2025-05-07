echo 'add 192.1.2.45 192.1.2.23 esp 4523 -m transport -u '${reqid_ipv4}'  -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
echo 'add 192.1.2.23 192.1.2.45 esp 2345 -m transport -u '${reqid_ipv4}' -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c

ipsec _kernel state
