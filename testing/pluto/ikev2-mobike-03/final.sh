ipsec whack --trafficstatus
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
: ==== cut ====
ipsec auto --status
: ==== restore IPs to prevent leaking into other tests that dont reboot first ===
hostname | grep road && (../../guestbin/ip.sh address show dev eth0 | grep 192.1.33.222 && ../../guestbin/ip.sh address del 192.1.33.222/24 dev eth0)
hostname | grep road && (../../guestbin/ip.sh address show dev eth0 | grep 192.1.3.209 || ../../guestbin/ip.sh address add 192.1.3.209/24 dev eth0)
: ==== tuc ====
