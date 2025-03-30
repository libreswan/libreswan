# Initiate; during IKE_AUTH the child should fail and the connection
# put on to the revival queue
ipsec up west-east
# expect the on-demand kernel policy
ipsec _kernel policy
