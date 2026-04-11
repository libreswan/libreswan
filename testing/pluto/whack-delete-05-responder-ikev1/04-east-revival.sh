# Confirm that east is trying to revive; note that with IKEv1, the
# Child (IPsec) SAs, and then the IKE (IPsec) SA gets deleted.  The
# below is the Child SA trying to revive using the doomed IKE SA.
# When the IKE SA is deleted, there'll be a further revival but with a
# few seconds delay.

../../guestbin/wait-for-pluto.sh --match '#2: connection is supposed to remain up'
