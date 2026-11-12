ipsec up westnet-eastnet-ikev1
../../guestbin/wait-for.sh --match 'CHILD_SA .* established' -- cat OUTPUT/east.charon.log
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
echo done
