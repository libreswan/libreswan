# should fail to establish the Child SA: pfs-info KE DH19 vs DH20 mismatch
ipsec whack --impair revival
ipsec auto --up westnet-eastnet-ikev2
# the IKE SA is up but the Child SA was rejected
ipsec whack --trafficstatus
echo done
