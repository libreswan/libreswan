/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn--ikev1
ipsec add addconn--ikev1--fragmentation-force

ipsec add addconn--ikev2
ipsec add addconn--ikev2--fragmentation-no
ipsec add addconn--ikev2--fragmentation-yes
ipsec add addconn--ikev2--fragmentation-force

ipsec whack --name whack--ikev1                      --host 1.2.3.4                       --no-esn --pfs --tunnel --encrypt --ikev1 --ipv4 --to --host 5.6.7.8
ipsec whack --name whack--ikev1--fragmentation-force --host 1.2.3.4 --fragmentation force --no-esn --pfs --tunnel --encrypt --ikev1 --ipv4 --to --host 5.6.7.8

ipsec whack --name whack--ikev2                      --host 1.2.3.4                       --no-esn --pfs --tunnel --encrypt --ikev2 --ipv4 --to --host 5.6.7.8
ipsec whack --name whack--ikev2--ikefrag-allow       --host 1.2.3.4 --ikefrag-allow       --no-esn --pfs --tunnel --encrypt --ikev2 --ipv4 --to --host 5.6.7.8
ipsec whack --name whack--ikev2--ikefrag-force       --host 1.2.3.4 --ikefrag-force       --no-esn --pfs --tunnel --encrypt --ikev2 --ipv4 --to --host 5.6.7.8

ipsec whack --name whack--ikev2--fragmentation-no    --host 1.2.3.4 --fragmentation no    --no-esn --pfs --tunnel --encrypt --ikev2 --ipv4 --to --host 5.6.7.8
ipsec whack --name whack--ikev2--fragmentation-yes   --host 1.2.3.4 --fragmentation yes   --no-esn --pfs --tunnel --encrypt --ikev2 --ipv4 --to --host 5.6.7.8
ipsec whack --name whack--ikev2--fragmentation-force --host 1.2.3.4 --fragmentation force --no-esn --pfs --tunnel --encrypt --ikev2 --ipv4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*\(IKEv[12]\).*/\1 \2/p'

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*IKE_FRAG_ALLOW.*/\1 IKE_FRAG_ALLOW/p'

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*IKE_FRAG_FORCE.*/\1 IKE_FRAG_FORCE/p'
