/testing/guestbin/swan-prep --nokeys

ipsec start
../../guestbin/wait-until-pluto-started

# bloat the first fragment
ipsec whack --impair add_unknown_v2_payload_to:IKE_AUTH:400
# and send some bonus fragments
ipsec whack --impair add_fragments:1:1024

ipsec add west-east
echo "initdone"
