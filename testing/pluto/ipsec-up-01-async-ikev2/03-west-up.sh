ipsec up --asynchronous west-cuckold
../../guestbin/wait-for.sh --match '#2:' -- ipsec trafficstatus

ipsec up --asynchronous west-cuckoo
../../guestbin/wait-for.sh --match '#3:' -- ipsec trafficstatus

../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ping-once.sh --up 192.0.20.254
ipsec trafficstatus
