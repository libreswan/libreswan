/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn
ipsec add addconn--compress=no
ipsec add addconn--compress=yes

ipsec add addconn--type=passthrough
ipsec add addconn--type=passthrough--compress=no
ipsec add addconn--type=passthrough--compress=yes

ipsec whack --name whack                               --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--no-compress   --no-compress  --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--compress      --compress     --encrypt --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--passthrough                               --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--no-compress   --no-compress  --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--compress      --compress     --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*COMPRESS.*/\1 COMPRESS/p'
