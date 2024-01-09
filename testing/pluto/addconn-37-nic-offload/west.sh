/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn

ipsec add addconn--nic-offload=no
ipsec add addconn--nic-offload=yes
ipsec add addconn--nic-offload=auto
ipsec add addconn--nic-offload=packet
ipsec add addconn--nic-offload=crypto

ipsec whack --name whack                                           --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--nic-offload        --nic-offload         --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--nic-offload=no     --nic-offload=no      --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--nic-offload=yes    --nic-offload=yes     --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--nic-offload=auto   --nic-offload=auto    --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--nic-offload=packet --nic-offload=packet  --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--nic-offload=crypto --nic-offload=crypto  --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--passthrough                                            --pass --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--passthrough--nic-offload         --nic-offload         --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--nic-offload=no      --nic-offload=no      --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--nic-offload=yes     --nic-offload=yes     --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--nic-offload=auto    --nic-offload=auto    --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--nic-offload=packet  --nic-offload=packet  --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--nic-offload=crypto  --nic-offload=crypto  --pass --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(^[^:]*:\).* \(nic-offload:[^;]*\);.*/\1 \2/p' | sort
