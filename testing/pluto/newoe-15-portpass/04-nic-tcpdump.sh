# expect two lines of plain text - there and back
sed -n -e 's/.*PLAINTEXT.*/PLAINTEXT/p' /tmp/nic.tcpdump.log
cp /tmp/nic.tcpdump.log OUTPUT/
