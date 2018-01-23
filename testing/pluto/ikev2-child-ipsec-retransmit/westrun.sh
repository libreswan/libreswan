# initial exchange
ipsec auto --up westnet-eastnet-ikev2a
# creat-child-sa request. Expected to fail due to firewall
# we expect east to re-answer our retransmits
# drop silently to avoid race conditions of kernel log
iptables -I INPUT -p udp --dport 500 -j DROP
ipsec auto --up westnet-eastnet-ikev2b
echo done
