ipsec up --asynchronous west-to-east

# step through the main mode exchange

../../guestbin/wait-for.sh --match '#1: sent Main Mode request' -- cat /tmp/pluto.log
../../guestbin/wait-for.sh --match 'IMPAIR: blocking inbound message 1'  -- cat /tmp/pluto.log
ipsec whack --impair drip_inbound:1

../../guestbin/wait-for.sh --match '#1: sent Main Mode I2' -- cat /tmp/pluto.log
../../guestbin/wait-for.sh --match 'IMPAIR: blocking inbound message 2'  -- cat /tmp/pluto.log
ipsec whack --impair drip_inbound:2

../../guestbin/wait-for.sh --match '#1: sent Main Mode I3' -- cat /tmp/pluto.log
../../guestbin/wait-for.sh --match 'IMPAIR: blocking inbound message 3'  -- cat /tmp/pluto.log
ipsec whack --impair drip_inbound:3

../../guestbin/wait-for.sh --match '#1: ISAKMP SA established' -- cat /tmp/pluto.log

# wait for quick mode response
../../guestbin/wait-for.sh --match '#2: sent Quick Mode request' -- cat /tmp/pluto.log
../../guestbin/wait-for.sh --match 'IMPAIR: blocking inbound message 4'  -- cat /tmp/pluto.log
