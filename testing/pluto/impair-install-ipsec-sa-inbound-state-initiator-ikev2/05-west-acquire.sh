# Trigger an acquire; this fast track the revival using
# CREATE_CHILD_SA and again it will fail
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
../../guestbin/wait-for-pluto.sh '#3: IMPAIR: revival'
