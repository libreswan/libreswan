# The first TCP races IPsec for who finishes first.  The second always
# uses IPsec.

echo TRIGGER-OE | socat - TCP:192.1.2.23:7,bind=192.1.3.209
../../guestbin/wait-for-pluto.sh --match  '#2: initiator established Child SA using #1'
echo TRIGGER-OE | socat - TCP:192.1.2.23:7,bind=192.1.3.209

# should show tunnel and no shunts, and non-zero traffic count

ipsec trafficstatus | sed -e 's/Bytes=[1-9][0-9]*,/Bytes=NNN,/g'
ipsec shuntstatus
echo done
