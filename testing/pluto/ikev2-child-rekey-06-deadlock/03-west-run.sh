ipsec auto --status | grep west
ipsec auto --up west
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec trafficstatus

# this rekey, #2->#3, should succeed
ipsec whack --rekey-ipsec --name west

# this rekey, #3->#4, which is running in the background should fail.
# The message is blocked by firewall rules added in 02-west-init.sh
ipsec whack --rekey-ipsec --name west --async

# this rekey, #?->#5, will block (waiting on the asynchronous rekey
# #3->#4) and then die.
ipsec whack --rekey-ipsec --name west

# above whack commands leave much to be desired when it comes to
# logging; get around it by grepping for the expected outcome.
#
# Note: need to strip of "MONTH(1) DATE(2) TIME(3): "; look for real
# log lines that just match states we're interested in.

cat /tmp/pluto.log | sed -n -e 's/^[^|#]*: \([^#|].* #[1-5]:\)/\1/p'
