# these conns should load
# whack testing
ipsec whack --name testmanual1 --encrypt --ikev2-propose --ikev2-allow --ipv4 --host 1.2.3.4 --authby=psk --to --host 2.3.4.5 --authby=rsasig
ipsec whack --name testmanual2 --encrypt --ikev2-propose --ikev2-allow --ipv4 --host 1.2.3.5 --authby=null --to --host 2.3.4.6 --authby=rsasig
ipsec whack --name testmanual3 --psk --encrypt --ikev2-propose --ikev2-allow --ipv4 --host 1.2.3.6 --authby=psk --to --host 2.3.4.7 --authby=psk
# parser testing
ipsec auto --add test-default
ipsec auto --add test-v1-secret
ipsec auto --add test-v1-rsasig
ipsec auto --add test-passthrough
ipsec auto --add test1
ipsec auto --add test2
ipsec auto --add test3
ipsec auto --add test5
ipsec auto --add test6
ipsec auto --add test7
ipsec auto --add test8
ipsec auto --add test9
echo "all remaining tests should fail"
# whack testing
ipsec whack --name failtestmanual1 --ikev2-propose --ikev2-allow --ipv4 --host 1.2.3.5 --authby=null --to --host 2.3.4.6 --authby=rsasig
ipsec whack --name failtestmanual2 --encrypt --ipv4 --host 1.2.3.5 --authby=null --to --host 2.3.4.6 --authby=rsasig
ipsec whack --name failtestmanual3 --psk --encrypt --ikev2-propose --ikev2-allow --ipv4 --host 1.2.3.4 --authby=null --to --host 2.3.4.5 --authby=rsasig
ipsec whack --name failtestmanual4 --rsasig --encrypt --ikev2-propose --ikev2-allow --ipv4 --host 1.2.3.4 --authby=null --to --host 2.3.4.5 --authby=rsasig
# parser testing
ipsec auto --add failtest0
ipsec auto --add failtest1
ipsec auto --add failtest2
ipsec auto --add failtest3
ipsec auto --add failtest4
ipsec auto --add failtest5
ipsec auto --add failtest6
ipsec auto --add failtest7
ipsec auto --add failtest8
ipsec auto --add failtest9
ipsec auto --add failtest10
echo "Showing policies of all loaded connections"
ipsec status | egrep 'policy: |our auth:'
echo done
