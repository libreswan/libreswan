# Grep east's log for all rate-limited UDP events and the limiter sentinel.
# Columns: plain RC_LOG lines start with 'packet from',
#          debug-stream (over-limit) lines start with '| ',
#          impair lines start with 'impair: '
grep -e '^packet from' -e '^| dropping packet with mangled IKE header' -e '^impair: ' /tmp/pluto.log