ipsec auto --up  westnet-eastnet-subnets
ipsec whack --trafficstatus
# allow rekey time
sleep 30
sleep 30
# will state number change after IKE rekey?
ipsec whack --trafficstatus
echo done
