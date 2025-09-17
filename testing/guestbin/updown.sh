$!/bin/sh

printenv > /tmp/updown.env

exec ipsec _updown "$@"
