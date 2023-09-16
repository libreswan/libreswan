/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn
ipsec add addconn--type=transport
ipsec add addconn--type=tunnel

ipsec whack --name whack                           --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--tunnel     --tunnel      --encrypt --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--transport  --transport   --encrypt --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*TUNNEL.*/\1 TUNNEL/p'
ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*TRANSPORT.*/\1 TRANSPORT/p'
