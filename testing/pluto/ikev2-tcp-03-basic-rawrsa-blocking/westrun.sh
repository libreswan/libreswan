ipsec whack --impair suppress_retransmits
ipsec whack --impair tcp_use_blocking_write
../../guestbin/libreswan-up-down.sh westnet-eastnet-ikev2 -I 192.0.1.254 192.0.2.254
