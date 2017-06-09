ipsec auto --up westnet-eastnet-sourceip
# not using -I because sourceip= should add the route
ping -n -c 4 192.0.2.254
ipsec whack --trafficstatus
