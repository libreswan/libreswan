echo 'add 198.18.1.12 198.18.1.15 esp 4523 -m tunnel -u 100 -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
echo 'add 198.18.1.15 198.18.1.12 esp 2345 -m tunnel -u 100 -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c

ifconfig ipsec1
ipsec _kernel state
ipsec _kernel policy
