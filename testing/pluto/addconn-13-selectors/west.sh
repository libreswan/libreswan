/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

# stock IKEv2
./host4.sh s0-s1 leftsubnet=	                  rightsubnet=1.1.1.1/32
./host4.sh s1-s1 leftsubnet=2.2.2.1/32            rightsubnet=1.1.1.1/32
./host4.sh s1-s2 leftsubnet=2.2.2.1/32            rightsubnet=1.1.1.1/32,1.1.1.2/32
./host4.sh s2-s1 leftsubnet=2.2.2.1/32,2.2.2.2/32 rightsubnet=1.1.1.1/32
./host4.sh s2-s2 leftsubnet=2.2.2.1/32,2.2.2.2/32 rightsubnet=1.1.1.1/32,1.1.1.2/32

# IKEv1 doesn't do multiple selectors
./host4.sh s1-s2 leftsubnet=2.2.2.1/32            rightsubnet=1.1.1.1/32,1.1.1.2/32 keyexchange=ikev1

# right is expanded to multiple connections
./host4.sh s0-ss1 leftsubnet=                      rightsubnets=1.1.1.1/32
./host4.sh s1-ss1 leftsubnet=2.2.2.1/32            rightsubnets=1.1.1.1/32
./host4.sh s1-ss2 leftsubnet=2.2.2.1/32            rightsubnets=1.1.1.1/32,1.1.1.2/32
./host4.sh s2-ss1 leftsubnet=2.2.2.1/32,2.2.2.2/32 rightsubnets=1.1.1.1/32
./host4.sh s2-ss2 leftsubnet=2.2.2.1/32,2.2.2.2/32 rightsubnets=1.1.1.1/32,1.1.1.2/32

# both left and right are expanded to multiple connections
./host4.sh ss0-ss1 leftsubnets=                      rightsubnets=1.1.1.1/32
./host4.sh ss1-ss1 leftsubnets=2.2.2.1/32            rightsubnets=1.1.1.1/32
./host4.sh ss1-ss2 leftsubnets=2.2.2.1/32            rightsubnets=1.1.1.1/32,1.1.1.2/32
./host4.sh ss2-ss1 leftsubnets=2.2.2.1/32,2.2.2.2/32 rightsubnets=1.1.1.1/32
./host4.sh ss2-ss2 leftsubnets=2.2.2.1/32,2.2.2.2/32 rightsubnets=1.1.1.1/32,1.1.1.2/32

# left accumulates both
./host4.sh s1ss1-s1 leftsubnet=2.2.2.1/32            leftsubnets=2.2.2.3/32            rightsubnet=1.1.1.1/32
./host4.sh s1ss2-s1 leftsubnet=2.2.2.1/32            leftsubnets=2.2.2.3/32,2.2.2.4/32 rightsubnet=1.1.1.1/32
./host4.sh s2ss1-s1 leftsubnet=2.2.2.1/32,2.2.2.2/32 leftsubnets=2.2.2.3/32            rightsubnet=1.1.1.1/32
./host4.sh s2ss2-s1 leftsubnet=2.2.2.1/32,2.2.2.2/32 leftsubnets=2.2.2.3/32,2.2.2.4/32 rightsubnet=1.1.1.1/32

# protoport only works with one subnet=
./host4.sh s0p  leftsubnet=                      leftprotoport=tcp/22
./host4.sh s1p  leftsubnet=2.2.2.1/32            leftprotoport=tcp/22
./host4.sh s2p  leftsubnet=2.2.2.1/32,2.2.2.2/32 leftprotoport=tcp/22

# however, protoport works with multiple subnets=
./host4.sh s0p  leftsubnets=                      leftprotoport=tcp/22
./host4.sh s1p  leftsubnets=2.2.2.1/32            leftprotoport=tcp/22
./host4.sh s2p  leftsubnets=2.2.2.1/32,2.2.2.2/32 leftprotoport=tcp/22
