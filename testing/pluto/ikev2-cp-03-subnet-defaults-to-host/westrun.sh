# this will ask for WEST/32, but get back an addresspool address
ipsec up west-eastnet
../../guestbin/ping-once.sh --up -I 100.64.13.2 192.0.2.254
ipsec trafficstatus
# confirm resolv.conf was NOT updated (ignore-peer-dns=yes)
cat /etc/resolv.conf
# confirm resolv.conf is unchanged on down
ipsec down west-eastnet
cat /etc/resolv.conf
echo done
