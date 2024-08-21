/testing/guestbin/swan-prep

ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn-narrowing=
ipsec add addconn-narrowing=no
ipsec add addconn-narrowing=yes

ipsec whack --name whack--narrowing=     --narrowing     --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--narrowing=no   --narrowing no  --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--narrowing=yes  --narrowing yes --encrypt --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--allow-narrowing  --allow-narrowing --encrypt --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*ALLOW_NARROWING.*/\1 ALLOW_NARROWING/p'
