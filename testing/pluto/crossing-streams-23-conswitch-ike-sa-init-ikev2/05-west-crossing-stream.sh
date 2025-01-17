# confirm that the peer's IKE SA established "a", and then the peer's
# Child SA needed to switch to "b" before establishing.

../../guestbin/wait-for-pluto.sh --match '"a" #2: responder established IKE SA'
../../guestbin/wait-for-pluto.sh --match '"a" #3: switched to "b"'
../../guestbin/wait-for-pluto.sh --match '"b" #3: responder established Child SA using #2'

# this is where pluto realises that the stream crossed
../../guestbin/wait-for-pluto.sh --match '#1: dropping negotiation'
../../guestbin/wait-for-pluto.sh --match '"a" #4: initiator established Child SA using #2'

../../guestbin/ping-once.sh --up -I 192.0.3.253 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.20.254
