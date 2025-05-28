ipsec auto --up north-pool
ipsec auto --up north-subnet1
ipsec auto --up north-subnet2
# Should show the lease ip is being used for all conns
ipsec whack --trafficstatus
