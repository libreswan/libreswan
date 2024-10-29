# expect two lines of plain text - there and back
../../guestbin/tcpdump.sh --stop -i eth1 -A | sed -n -e 's/.*PLAINTEXT.*/PLAINTEXT/p'
