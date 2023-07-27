/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --name whack--ikefrag-default  --host 1.2.3.4                 --no-esn --pfs --tunnel --ecdsa --encrypt --ikev2-allow --ipv4 --to --host 5.6.7.8
ipsec whack --name whack--ikefrag-allow    --host 1.2.3.4 --ikefrag-allow --no-esn --pfs --tunnel --ecdsa --encrypt --ikev2-allow --ipv4 --to --host 5.6.7.8
ipsec whack --name whack--ikefrag-force    --host 1.2.3.4 --ikefrag-force --no-esn --pfs --tunnel --ecdsa --encrypt --ikev2-allow --ipv4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*IKE_FRAG_ALLOW.*/\1 IKE_FRAG_ALLOW/p'

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*IKE_FRAG_FORCE.*/\1 IKE_FRAG_FORCE/p'
