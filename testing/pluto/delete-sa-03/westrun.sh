ipsec auto --up west-east
ipsec auto --up west-east-b
ipsec auto --up west-east-c
ipsec auto --status | grep west-
# This down should not delete #1 because that IKE SA is also used by b and c
ipsec auto --down west-east
ipsec status |grep west-
