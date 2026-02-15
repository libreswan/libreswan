/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec addconn --name nic-offload=        #nic-offload=
ipsec addconn --name nic-offload=no      nic-offload=no
ipsec addconn --name nic-offload=yes     nic-offload=yes
ipsec addconn --name nic-offload=packet  nic-offload=packet
ipsec addconn --name nic-offload=crypto  nic-offload=crypto

ipsec addconn --name type=transport-nic-offload=packet  type=transport nic-offload=packet
ipsec addconn --name type=tunnel-nic-offload=packet     type=tunnel    nic-offload=packet

ipsec addconn --name phase2=esp-type=transport-nic-offload=packet  phase2=esp type=transport nic-offload=packet
ipsec addconn --name phase2=ah-type=transport-nic-offload=packet   phase2=ah  type=transport nic-offload=packet

ipsec addconn --name compress=yes-type=transport-nic-offload=packet  compress=yes type=transport nic-offload=packet
ipsec addconn --name compress=no-type=transport-nic-offload=packet   compress=no  type=transport nic-offload=packet

ipsec addconn --name encapsulation=yes-type=transport-nic-offload=packet   encapsulation=yes  type=transport nic-offload=packet
ipsec addconn --name encapsulation=no-type=transport-nic-offload=packet    encapsulation=no   type=transport nic-offload=packet
ipsec addconn --name encapsulation=auto-type=transport-nic-offload=packet  encapsulation=auto type=transport nic-offload=packet

#

ipsec whack --name whack                                           --transport --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--nic-offload-x      --nic-offload x       --transport --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--nic-offload=no     --nic-offload=no      --transport --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--nic-offload=yes    --nic-offload=yes     --transport --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--nic-offload=packet --nic-offload=packet  --transport --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--nic-offload=crypto --nic-offload=crypto  --transport --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--passthrough                                            --pass --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--passthrough--nic-offload=no      --nic-offload=no      --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--nic-offload=yes     --nic-offload=yes     --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--nic-offload=packet  --nic-offload=packet  --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--nic-offload=crypto  --nic-offload=crypto  --pass --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(^[^:]*:\).* \(nic-offload:[^;]*\);.*/\1 \2/p' | sort
