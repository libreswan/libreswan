/testing/guestbin/swan-prep --46 --nokey

# default is to use WHACK_BASIC_MAGIC

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --shutdown

# force shutdown with current WHACK_MAGIC (aka 0) and not
# WHACK_BASIC_MAGIC

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --shutdown --magic 0

# try legacy WHACK_MAGIC=1869114161 from 4.x and 5.0, should fail

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --shutdown --magic 1869114161 | sed -e 's/should be [0-9]*/should be .../'
