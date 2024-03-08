# wait for ROAD to block on revival
../../guestbin/wait-for-pluto.sh "IMPAIR: redirect"
ipsec whack --impair trigger_revival:1
../../guestbin/ping-once.sh --up 192.0.2.254
