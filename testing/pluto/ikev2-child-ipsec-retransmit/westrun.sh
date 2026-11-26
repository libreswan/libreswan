ipsec whack --impair revival

# initial exchange
ipsec up westnet-eastnet-ikev2a # sanitize-retransmits

# CREATE_CHILD_SA request.  Expected to fail due to firewall we expect
# east to re-answer our retransmits drop silently to avoid race
# conditions of kernel log

iptables -I INPUT -p udp --dport 500 -j DROP
ipsec up westnet-eastnet-ikev2b # expect retransmits

echo done
