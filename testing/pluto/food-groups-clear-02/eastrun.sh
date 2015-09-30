: we expect that east can ping west
ping -n -c 1 -n 192.1.2.45

: we expect that this will result no tunnel, as we are not prepared for
: a tunnel, but west will attempt it.
ping -n -c 2 -n 192.0.1.3

: make sure we can still ping west.
ping -n -c 1 -n 192.1.2.45

ipsec look

echo end

