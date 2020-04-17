# first conn is already loaded, do the second one now
ipsec whack --name whack----rsasig --host 1.2.3.4 --ikefrag-allow --no-esn --pfs --tunnel --rsasig --encrypt --ikev2-allow --ipv4 --to --host 5.6.7.8
ipsec whack --name whack-----ecdsa --host 1.2.3.4 --ikefrag-allow --no-esn --pfs --tunnel --ecdsa --encrypt --ikev2-allow --ipv4 --to --host 5.6.7.8
ipsec whack --name whack--defaults --host 1.2.3.4 --ikefrag-allow --no-esn --pfs --tunnel --encrypt --ikev2-allow --ipv4 --to --host 5.6.7.8
ipsec whack --name whack--ikev2-default --host 1.2.3.4 --ikefrag-allow --no-esn --pfs --tunnel --encrypt --ipv4 --to --host 5.6.7.8
ipsec status | grep "policy:" | grep rsasig | grep TUNNEL
echo ""
ipsec status | grep "policy:" | grep defaults | grep TUNNEL
echo ""
ipsec status | grep "hash-policy:" | grep rsasig
echo ""
ipsec status | grep "hash-policy:" | grep defaults
echo ""
ipsec status | grep "TUNNEL" | grep ikev2-default | sed "s/^.*\(IKEV._ALLOW\).*$/\1/"
echo done
