/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn

ipsec add addconn--nic-offload=no
ipsec add addconn--nic-offload=yes
ipsec add addconn--nic-offload=packet
ipsec add addconn--nic-offload=crypto

# should fail to load
ipsec add addconn-encapsulation=yes

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
