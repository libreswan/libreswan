# wait for it to re-establish
../../guestbin/wait-for.sh --match east -- ipsec whack --trafficstatus | sed -e 's/192.0.2.10[1-2]/192.0.2.10x/'
../../guestbin/ping-once.sh --up 192.0.2.254
echo really done
