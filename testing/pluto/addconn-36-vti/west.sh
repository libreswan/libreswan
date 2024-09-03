/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn

ipsec add addconn--vti-shared=no
ipsec add addconn--vti-shared=yes

ipsec add addconn--vti-routing=no
ipsec add addconn--vti-routing=yes

ipsec add addconn--vti-interface=short
ipsec add addconn--vti-interface=long

ipsec whack --name whack                                      --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--vti-shared       --vti-shared       --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--vti-shared=no    --vti-shared=no    --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--vti-shared=yes   --vti-shared=yes   --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--vti-routing      --vti-routing      --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--vti-routing=no   --vti-routing=no   --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--vti-routing=yes  --vti-routing=yes  --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--vti-interface        --vti-interface          --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--vti-interface=short  --vti-interface=short    --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--vti-interface=long   --vti-interface=very-very-very-very-long-name  --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--passthrough                                      --pass --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--passthrough--vti-shared       --vti-shared       --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--vti-shared=no    --vti-shared=no    --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--vti-shared=yes   --vti-shared=yes   --pass --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--passthrough--vti-routing      --vti-routing      --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--vti-routing=no   --vti-routing=no   --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--passthrough--vti-routing=yes  --vti-routing=yes  --pass --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(^[^:]*:\).* \(vti-routing:[^;]*\);.*/\1 \2/p' | sort
ipsec connectionstatus | sed -n -e 's/\(^[^:]*:\).* \(vti-shared:[^;]*\);.*/\1 \2/p' | sort
