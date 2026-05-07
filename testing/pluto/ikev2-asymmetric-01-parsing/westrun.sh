# these conns should load
# whack testing
ipsec whack --name testmanual1 --encrypt --ikev2 --ipv4 --host 1.2.3.4 --authby=psk --to --host 2.3.4.5 --authby=rsasig
ipsec whack --name testmanual2 --encrypt --ikev2 --ipv4 --host 1.2.3.5 --authby=null --to --host 2.3.4.6 --authby=rsasig
ipsec whack --name testmanual3 --psk --encrypt --ikev2 --ipv4 --host 1.2.3.6 --authby=psk --to --host 2.3.4.7 --authby=psk
# parser testing
ipsec add test-default
ipsec add test-v1-secret
ipsec add test-v1-rsasig
ipsec add test-passthrough
ipsec add test1
ipsec add test2
ipsec add test3
ipsec add test5
ipsec add test6
ipsec add test7
ipsec add test8
ipsec add test9
ipsec add test10
ipsec add test11
echo "all remaining tests should fail"
# whack testing
ipsec whack --name failtestmanual1 --ikev2 --ipv4 --host 1.2.3.5 --authby=null --to --host 2.3.4.6 --authby=rsasig
ipsec whack --name failtestmanual2 --ikev1 --encrypt --ipv4 --host 1.2.3.5 --authby=null --to --host 2.3.4.6 --authby=rsasig
# parser testing
ipsec add failtest0
ipsec add failtest1
ipsec add failtest3
ipsec add failtest4
ipsec add failtest5
ipsec add failtest6
ipsec add failtest7
ipsec add failtest8
ipsec add failtest9
ipsec add failtest10
ipsec add failtest11
echo "Showing policies of all loaded connections"
ipsec status | grep -E 'policy: |our auth:'
echo done
