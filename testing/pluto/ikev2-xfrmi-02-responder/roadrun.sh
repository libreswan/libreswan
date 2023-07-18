ipsec auto --up road
# give few seconds for tcpdump on east to sync output file
sleep 5
# do not send a ping yet. It would confuse the tcpdump output
# ping -w 4 -c 4 192.1.2.23
echo done
