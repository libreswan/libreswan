# wait for east to initiate to us

../../guestbin/wait-for-pluto.sh --match '#1: .* established'
../../guestbin/wait-for-pluto.sh --match '#2: .* established'

ipsec trafficstatus

# use delete, not down - because east has auto=start
ipsec delete west-east-auto

# no IPsec SA should be there. No ISAKMP SA should be there either
ipsec trafficstatus
ipsec connectionstatus
