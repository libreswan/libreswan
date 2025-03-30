ipsec whack --trafficstatus
ipsec _kernel state
ip xfrm policy
grep "MOBIKE " /tmp/pluto.log | sed -e '/Message ID:/ s/;.*//'
sleep 7
: ==== cut ====
ipsec auto --status
: ==== restore IPs to prevent leaking into other tests that dont reboot first ===
hostname | grep road && (../../guestbin/ip.sh address show dev eth0 | grep 192.1.3.209 || ../../guestbin/ip.sh address add 192.1.3.209/24 dev eth0)
: ==== tuc ====
