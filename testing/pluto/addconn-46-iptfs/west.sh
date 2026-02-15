/testing/guestbin/swan-prep --nokeys

ipsec start
../../guestbin/wait-until-pluto-started

ipsec addconn --name iptfs=    #iptfs=
ipsec addconn --name iptfs=no  iptfs=no
ipsec addconn --name iptfs=yes iptfs=yes

ipsec addconn --name type=passthrough-iptfs=    type=passthrough #iptfs=
ipsec addconn --name type=passthrough-iptfs=no  type=passthrough iptfs=no
ipsec addconn --name type=passthrough-iptfs=yes type=passthrough iptfs=yes

ipsec addconn --name type=transport-iptfs=    type=transport #iptfs=
ipsec addconn --name type=transport-iptfs=no  type=transport iptfs=no
ipsec addconn --name type=transport-iptfs=yes type=transport iptfs=yes

ipsec addconn --name type=tunnel-iptfs=    type=tunnel #iptfs=
ipsec addconn --name type=tunnel-iptfs=no  type=tunnel iptfs=no
ipsec addconn --name type=tunnel-iptfs=yes type=tunnel iptfs=yes

ipsec addconn --name keyexchange=ikev1-iptfs=    keyexchange=ikev1 #iptfs=
ipsec addconn --name keyexchange=ikev1-iptfs=no  keyexchange=ikev1 iptfs=no
ipsec addconn --name keyexchange=ikev1-iptfs=yes keyexchange=ikev1 iptfs=yes

ipsec whack --name whack                     --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--iptfs      --iptfs     --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--iptfs=no   --iptfs=no  --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--iptfs=yes  --iptfs=yes --encrypt --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*PFS.*/\1 PFS/p' | sort
