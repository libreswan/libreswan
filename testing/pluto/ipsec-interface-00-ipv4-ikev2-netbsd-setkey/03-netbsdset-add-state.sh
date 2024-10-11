echo 'add 198.18.1.12 198.18.1.15 esp 4523 -m transport -u 16385 -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
echo 'add 198.18.1.15 198.18.1.12 esp 2345 -m transport -u 16386 -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c

../../guestbin/ipsec-kernel-state.sh
