/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
# parser---* connections from west.conf loaded

ipsec whack --name whack----rsasig      --host 1.2.3.4 --ikefrag-allow --no-esn --pfs --tunnel --rsasig --encrypt --ikev2-allow --ipv4 --to --host 5.6.7.8
ipsec whack --name whack-----ecdsa      --host 1.2.3.4 --ikefrag-allow --no-esn --pfs --tunnel --ecdsa  --encrypt --ikev2-allow --ipv4 --to --host 5.6.7.8
ipsec whack --name whack--defaults      --host 1.2.3.4 --ikefrag-allow --no-esn --pfs --tunnel          --encrypt --ikev2-allow --ipv4 --to --host 5.6.7.8
ipsec whack --name whack--ikev2-default --host 1.2.3.4 --ikefrag-allow --no-esn --pfs --tunnel          --encrypt               --ipv4 --to --host 5.6.7.8

ipsec connectionstatus | grep "policy:" | grep rsasig | grep TUNNEL

ipsec connectionstatus | grep "policy:" | grep defaults | grep TUNNEL

ipsec connectionstatus | grep "hash-policy:" | grep rsasig

ipsec connectionstatus | grep "hash-policy:" | grep defaults

ipsec connectionstatus | grep "TUNNEL" | grep ikev2-default | sed "s/^.*policy: \(IKEv.\).*$/\1/"
