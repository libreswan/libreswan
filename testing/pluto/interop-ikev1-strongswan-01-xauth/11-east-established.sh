../../guestbin/wait-for.sh --match 'CHILD_SA .* established' -- cat /tmp/charon.log | sed -e 's/.*\(CHILD.*established\).*/\1/'
