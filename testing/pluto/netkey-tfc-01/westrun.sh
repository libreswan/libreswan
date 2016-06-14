ipsec auto --up tfc
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# byte counters appear for unencrypted size, not encrypted/padded size
ipsec whack --trafficstatus
echo done
