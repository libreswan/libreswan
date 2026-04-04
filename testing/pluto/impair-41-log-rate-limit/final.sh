# On EAST this will show the dropped packets and the log-limiter
# reaching its limit.  Because of a quirk in the implementation, the
# limit reached message appears before the final log.  After the final
# message there should be a debug-log message.

grep -e '^packet from' -e '^| dropping packet with mangled IKE header' -e '^impair: ' /tmp/pluto.log
