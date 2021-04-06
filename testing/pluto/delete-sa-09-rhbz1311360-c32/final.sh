sleep 1
# Expecting the IKE SA of west-east and the IPsec SA of westnet-eastnet
ipsec status |grep STATE
