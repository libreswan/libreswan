ipsec whack --impair retransmits
# expected to fail due to overlap of IP
ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate
echo done
