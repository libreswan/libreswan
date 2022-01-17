# wait for the child to start a liveness probe; this is the first clue
../../guestbin/wait-for.sh --match ': retransmission; will wait 1 second' -- cat /tmp/pluto.log
