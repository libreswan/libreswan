/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --name order-test --tunnel --encrypt --ipv4 --tunnelipv6  --host 1.2.3.4 --id '@foo' --client fe80::1/128 --to --host 2.3.4.5 --id '@bar' --client fe80::2/128
ipsec whack --connectionstatus --name order-test
