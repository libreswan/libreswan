# look for Message ID of probe that will die
../../guestbin/wait-for.sh --match 'sent message request 0' -- sed -n -e 's/ (.*/ (...)/p' /tmp/pluto.log
# now check things died
../../guestbin/wait-for-pluto.sh ' liveness action '
# finally check there was never a response
../../guestbin/wait-for.sh --no-match 'received message response 0' -- sed -n -e 's/ (.*/ (...)/p' /tmp/pluto.log
