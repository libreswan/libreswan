ipsec whack --trafficstatus
../../guestbin/ipsec-look.sh
: ==== cut ====
ipsec auto --status
: ==== restore IPs to prevent leaking into other tests that dont reboot first ===
hostname | grep road && (ip addr show dev eth0 | grep 192.1.33.222 && ip addr del 192.1.33.222/24 dev eth0)
hostname | grep road && (ip addr show dev eth0 | grep 192.1.3.209 || ip addr add 192.1.3.209/24 dev eth0)
: ==== tuc ====
