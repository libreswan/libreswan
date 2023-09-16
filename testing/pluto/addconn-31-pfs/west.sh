/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn
ipsec add addconn--pfs=no
ipsec add addconn--pfs=yes

ipsec add addconn--type=passthrough
ipsec add addconn--type=passthrough--pfs=no
ipsec add addconn--type=passthrough--pfs=yes

ipsec whack --name whack                     --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--pfs=no   --no-pfs  --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--pfs=yes  --pfs     --encrypt --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--passthrough                     --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--pfs=no   --no-pfs  --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--pfs=yes  --pfs     --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*PFS.*/\1 PFS/p'
