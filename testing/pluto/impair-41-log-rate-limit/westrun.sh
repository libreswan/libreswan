# Send different sized packets so that the limited log can be
# recognized based on the packet length.

# This should tickle the log limit but doesn't see #2727
echo "asdf" | nc -4 -u 192.1.2.23 4500

# This tickles demux.c's code.

# under limit
printf '\0\0\0\0a' | nc -4 -u 192.1.2.23 4500
# at limit
printf '\0\0\0\0as' | nc -4 -u 192.1.2.23 4500
# over limit -> debug log
printf '\0\0\0\0asd' | nc -4 -u 192.1.2.23 4500
