# north is redirected to 2 - 192.1.2.45 - which is up
ipsec whack --impair none
ipsec whack --impair revival --impair suppress_retransmits
ipsec auto --add north-east
ipsec auto --up north-east
ipsec whack --impair trigger_revival:3
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --delete north-east
