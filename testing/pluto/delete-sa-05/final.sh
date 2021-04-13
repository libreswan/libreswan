# one IPsec SA should be up and one ISAKMP SA should be there
# on west no other states should be there, but on east there
# should be an attempt for the deleted IPsec SA to be restarted
ipsec whack --trafficstatus
ipsec status |grep west-east |grep STATE_
