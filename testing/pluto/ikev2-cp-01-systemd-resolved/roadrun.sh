# update from blank

resolvectl dns eth0
resolvectl domain eth0
ipsec up eastnet-any
resolvectl dns eth0
resolvectl domain eth0

../../guestbin/ping-once.sh --up -I 100.64.13.2 192.0.2.254
ipsec whack --trafficstatus

# restore to blank

ipsec down eastnet-any
resolvectl dns eth0
resolvectl domain eth0

# update from non-blank

resolvectl dns eth0 8.8.8.8
resolvectl domain eth0 google.com
ipsec up eastnet-any
resolvectl dns eth0
resolvectl domain eth0

# restore to non-blank

ipsec down eastnet-any
resolvectl dns eth0
resolvectl domain eth0

echo done
