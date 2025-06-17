/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn

ipsec add addconn--phase2=esp
ipsec add addconn--phase2=ah

ipsec add addconn--phase2=esp--ah=sha1--esp=aes
ipsec add addconn--phase2=ah--ah=sha1--esp=aes

ipsec add addconn--esp=aes
ipsec add addconn--ah=sha1

ipsec add addconn--type=passthrough
ipsec add addconn--type=passthrough--phase2=esp
ipsec add addconn--type=passthrough--phase2=ah

ipsec whack --name whack                              --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--encrypt      --encrypt      --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--authenticate --authenticate --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--pass                              --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--pass--encrypt      --encrypt      --pass --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--pass--authenticate --authenticate --pass --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*ENCRYPT.*/\1 ENCRYPT/p'
ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*AUTHENTICATE.*/\1 AUTHENTICATE/p'
