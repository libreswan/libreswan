/testing/guestbin/swan-prep --nokeys

ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn
ipsec add addconn--iptfs=no
ipsec add addconn--iptfs=yes

ipsec add addconn--type=passthrough
ipsec add addconn--type=passthrough--iptfs=no
ipsec add addconn--type=passthrough--iptfs=yes

ipsec whack --name whack                     --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--iptfs      --iptfs     --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--iptfs=no   --iptfs=no  --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--iptfs=yes  --iptfs=yes --encrypt --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--passthrough                     --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--iptfs      --iptfs     --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--iptfs=no   --iptfs=no  --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--iptfs=yes  --iptfs=yes --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*PFS.*/\1 PFS/p' | sort
