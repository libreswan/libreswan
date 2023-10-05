/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn
ipsec add addconn--encapsulation=no
ipsec add addconn--encapsulation=yes
ipsec add addconn--encapsulation=auto

ipsec add addconn--type=passthrough
ipsec add addconn--type=passthrough--encapsulation=no
ipsec add addconn--type=passthrough--encapsulation=yes
ipsec add addconn--type=passthrough--encapsulation=auto

ipsec whack --name whack                                            --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--encapsulation=no    --encapsulation=no    --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--encapsulation=yes   --encapsulation=yes   --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--encapsulation=auto  --encapsulation=auto  --encrypt --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--passthrough                                          --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--encapsulation=no   --encapsulation=no   --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--encapsulation=yes  --encapsulation=yes  --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--encapsulation=auto --encapsulation=auto --pass --auth-never --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(^[^:]*:\).* \(encaps:[^;]*\);.*/\1 \2/p'
