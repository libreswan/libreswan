# the IKE_SA_INIT response is inbound message 1, drop the IKE_AUTH response, 2
ipsec whack --impair drop_inbound:2
ipsec up --asynchronous westnet-eastnet-ipv4-psk-ikev2
# the IKE_AUTH request is out, so the larval Child SA exists
../../guestbin/wait-for.sh --match '#2:' -- ipsec showstates
# delete the larval Child SA while the IKE_AUTH response is outstanding
ipsec whack --deletestate 2
# now let the IKE_AUTH response arrive
ipsec whack --impair drip_inbound:2
# west no longer expects a Child SA so rejects the response, deleting the IKE SA
sleep 5
ipsec showstates
echo done
