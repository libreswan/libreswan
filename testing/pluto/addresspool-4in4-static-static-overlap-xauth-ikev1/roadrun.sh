ipsec whack --impair revival
# expected to fail due to overlap of IP
ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate # sanitize-retransmits
echo done
