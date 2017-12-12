ipsec auto --up  westnet-eastnet
# counters are zero
ipsec whack --trafficstatus
echo take-passthrough-unencrpted | nc -s 192.0.1.254 192.0.2.254 22
# still zero
ipsec whack --trafficstatus
echo take-conn-encrypted | nc -s 192.0.1.254 192.0.2.254 222
# this moved through the tunnel, so non-zero
ipsec whack --trafficstatus
echo done
