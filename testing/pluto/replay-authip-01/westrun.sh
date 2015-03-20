cat authip-rogue.raw | nc -w 5 -u -s 192.1.2.45 -p 500 192.1.2.23 500 >/dev/null 2>/dev/null
sleep 2
echo done
