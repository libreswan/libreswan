# now config for pluto; importing key

east# /testing/guestbin/swan-prep --nokeys
west# /testing/guestbin/swan-prep --nokeys

east# /testing/x509/import.sh real/mained/east.p12
west# /testing/x509/import.sh real/mained/west.p12

east# ipsec start
west# ipsec start

east# ../../guestbin/wait-until-pluto-started
west# ../../guestbin/wait-until-pluto-started

east# ipsec add eddsa-east
west# ipsec add eddsa-west

east# ipsec whack --impair suppress-retransmits
west# ipsec whack --impair suppress-retransmits

# initdone

# west westrun.sh

west# ipsec up eddsa-west
west# ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
west# ipsec trafficstatus
west# ipsec listpubkeys

# test delete/free

west# ipsec delete westnet-eastnet-ikev2
