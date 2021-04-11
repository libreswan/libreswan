sleep 17
ping -n -q -c 2 -I 192.0.3.254 192.0.2.254
# there should be only two Child SA
echo done
