ping -f -c 100000 -I  192.0.3.254  192.0.2.254 2>&1 >/dev/null &
ping -f -c 100000 -I  192.0.3.254  192.0.2.251 2>&1 >/dev/null &
ping -f -c 100000 -I  192.0.3.254  192.0.22.254 2>&1 >/dev/null &
ping -f -c 100000 -I  192.0.3.254  192.0.22.251 2>&1 >/dev/null &
ipsec auto --add north-eastnets
ipsec auto --up north-eastnets
sleep 16
ping -n -c 2 -I 192.0.3.254 192.0.2.254
# should end up traffic flowing wheather tehre are 2 or more tunnels
echo done
