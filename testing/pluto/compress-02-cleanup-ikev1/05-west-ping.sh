# these small pings won't be compressed
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus

# test compression via large pings that can be compressed on IPCOMP SA
../../guestbin/ping-once.sh --up --large -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up --large -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up --large -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up --large -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus | sed -e 's/Bytes=\([1-9]\)[0-9][0-9],/Bytes=\1nn,/g'

ipsec _kernel state
ipsec _kernel policy
ipsec auto --down westnet-eastnet-compress | sed -e 's/=\([1-9]\)[0-9][0-9]B/=\1nnB/g'

: ping done
