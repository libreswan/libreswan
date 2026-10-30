/testing/guestbin/swan-prep --nokeys

ipsec start
../../guestbin/wait-until-pluto-started

# bloat the first fragment
ipsec whack --impair add_unknown_v2_payload_to:IKE_AUTH:400

# And send some bonus fragments making the total 64.  Once over heads
# are factored in, the packets exceed 64k in total.
ipsec whack --impair add_fragments:63:1024

ipsec add west-east
echo "initdone"
