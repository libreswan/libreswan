# the IKE SA uses DH19 but the Child SA pfs-info KE (esp=) is DH20
ipsec auto --up west-east
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec whack --trafficstatus
