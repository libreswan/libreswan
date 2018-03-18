ipsec whack --impair suppress-retransmits
# this should fail AUTH on mismatched CA
ipsec whack --oppohere 192.1.2.45 --oppothere 192.1.2.23
echo done
