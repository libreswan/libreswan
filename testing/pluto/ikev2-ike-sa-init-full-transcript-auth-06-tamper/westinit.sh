/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
ipsec whack --impair omit_v2_notification:IKE_SA_INIT_FULL_TRANSCRIPT_AUTH
echo "initdone"
