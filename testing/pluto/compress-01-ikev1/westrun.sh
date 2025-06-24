ipsec auto --up westnet-eastnet-compress
# these small pings won't be compressed
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# test compression via large pings that can be compressed on IPCOMP SA
../../guestbin/ping-once.sh --up --large -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up --large -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up --large -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up --large -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus | sed -e 's/Bytes=6[0-9][0-9],/Bytes=6nn,/g'
echo done
