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
ipsec whack --name whack--compress      --compress     --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--compress=no   --compress=no  --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--compress=yes  --compress=yes --encrypt --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--passthrough                               --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--compress      --compress     --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--compress=no   --compress=no  --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--compress=yes  --compress=yes --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*COMPRESS.*/\1 COMPRESS/p' | sort
